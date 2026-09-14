package starlark

import (
	"context"
	"fmt"
	"golang.org/x/net/http/httpguts"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"ads-httpproxy/pkg/logging"

	"go.starlark.net/lib/json"
	"go.starlark.net/lib/math"
	star_time "go.starlark.net/lib/time"
	"go.starlark.net/starlark"
	"go.starlark.net/starlarkstruct"
	"go.uber.org/zap"
)

type ThreatChecker interface {
	CheckURLViaCache(ctx context.Context, url string) (bool, int, string, error)
}

type StarlarkEngine struct {
	scriptPath string
	threatMgr  ThreatChecker
	mu         sync.RWMutex
	program    *starlark.Program
	globals    starlark.StringDict
	stopWatch  chan struct{}
	closeOnce  sync.Once
}

func NewEngine(scriptPath string, threatMgr ThreatChecker) (*StarlarkEngine, error) {
	e := &StarlarkEngine{
		scriptPath: scriptPath,
		threatMgr:  threatMgr,
		stopWatch:  make(chan struct{}),
	}
	if err := e.Reload(); err != nil {
		return nil, err
	}
	e.startWatcher()
	return e, nil
}

func (e *StarlarkEngine) Name() string {
	return "starlark"
}

func (e *StarlarkEngine) Reload() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Load the script
	thread := &starlark.Thread{Name: "main"}
	thread.SetMaxExecutionSteps(100000)
	thread.Print = func(_ *starlark.Thread, msg string) {
		if logging.Logger != nil {
			logging.Logger.Debug("Starlark", zap.String("msg", msg))
		}
	}

	// Build full ThreatScript module ecosystem
	threatScriptModules := BuildThreatScriptModules(e.threatMgr)

	predeclared := starlark.StringDict{
		"json": json.Module,
		"math": math.Module,
		"time": star_time.Module,
	}

	for name, module := range threatScriptModules {
		predeclared[name] = module
	}

	globals, err := starlark.ExecFile(thread, e.scriptPath, nil, predeclared)
	if err != nil {
		return fmt.Errorf("starlark exec error: %w", err)
	}

	if _, ok := globals["on_request"].(starlark.Callable); !ok {
		return fmt.Errorf("script must define 'on_request(req)' function")
	}

	globals.Freeze()
	e.globals = globals
	return nil
}

func headerDict(headers http.Header) *starlark.Dict {
	result := starlark.NewDict(len(headers))
	for key := range headers {
		_ = result.SetKey(starlark.String(key), starlark.String(headers.Get(key)))
	}
	return result
}
func applyHeaders(headers http.Header, values *starlark.Dict) error {
	updated := make(map[string]string, values.Len())
	for _, item := range values.Items() {
		key, ok := starlark.AsString(item[0])
		if !ok || !httpguts.ValidHeaderFieldName(key) {
			return fmt.Errorf("invalid script header name")
		}
		value, ok := starlark.AsString(item[1])
		if !ok || strings.ContainsAny(value, "\r\n") {
			return fmt.Errorf("invalid script header value")
		}
		updated[http.CanonicalHeaderKey(key)] = value
	}
	for key := range headers {
		if _, ok := updated[http.CanonicalHeaderKey(key)]; !ok {
			headers.Del(key)
		}
	}
	for key, value := range updated {
		if headers.Get(key) != value {
			headers.Set(key, value)
		}
	}
	return nil
}
func (e *StarlarkEngine) call(ctx context.Context, hook string, value starlark.Value) error {
	e.mu.RLock()
	callback := e.globals[hook]
	e.mu.RUnlock()
	if callback == nil {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	thread := &starlark.Thread{Name: hook}
	thread.SetMaxExecutionSteps(100000)
	thread.Print = func(_ *starlark.Thread, msg string) {
		if logging.Logger != nil {
			logging.Logger.Debug("Starlark", zap.String("msg", msg))
		}
	}
	stop := context.AfterFunc(ctx, func() { thread.Cancel("request context canceled") })
	defer stop()
	result, err := starlark.Call(thread, callback, starlark.Tuple{value}, nil)
	if err != nil {
		return fmt.Errorf("%s script: %w", hook, err)
	}
	if result == starlark.None {
		return nil
	}
	if block, ok := result.(starlark.Bool); ok {
		if block {
			return context.Canceled
		}
		return nil
	}
	if decision, ok := result.(*starlark.Dict); ok {
		action, found, err := decision.Get(starlark.String("action"))
		if err != nil {
			return err
		}
		if found {
			if text, ok := starlark.AsString(action); ok {
				switch text {
				case "allow":
					return nil
				case "block":
					return context.Canceled
				}
			}
		}
	}
	return fmt.Errorf("%s must return a boolean, None, or an action allow/block dictionary", hook)
}
func (e *StarlarkEngine) OnRequest(ctx context.Context, req *http.Request) error {
	headers := headerDict(req.Header)
	reqData := starlarkstruct.FromStringDict(starlark.String("request"), starlark.StringDict{
		"method": starlark.String(req.Method), "url": starlark.String(req.URL.String()), "host": starlark.String(req.Host), "remote": starlark.String(req.RemoteAddr), "headers": headers,
	})
	if err := e.call(ctx, "on_request", reqData); err != nil {
		return err
	}
	return applyHeaders(req.Header, headers)
}

func (e *StarlarkEngine) starlarkCheckUrl(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var urlStr string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "url", &urlStr); err != nil {
		return nil, err
	}

	if e.threatMgr == nil {
		return starlark.MakeInt(0), nil
	}

	// Starlark doesn't easily thread native Go contexts, so we use a background standard
	ctx := context.Background()
	blocked, score, cat, err := e.threatMgr.CheckURLViaCache(ctx, urlStr)
	if err != nil {
		logging.Logger.Warn("Starlark CheckURL failed", zap.Error(err))
		return starlark.MakeInt(0), nil
	}

	_ = blocked // Could expose this as a struct, but returning score is more dynamic
	_ = cat

	return starlark.MakeInt(score), nil
}

func (e *StarlarkEngine) OnResponse(ctx context.Context, resp *http.Response) error {
	if resp == nil {
		return nil
	}
	headers := headerDict(resp.Header)
	value := starlarkstruct.FromStringDict(starlark.String("response"), starlark.StringDict{"status_code": starlark.MakeInt(resp.StatusCode), "headers": headers})
	if err := e.call(ctx, "on_response", value); err != nil {
		return err
	}
	return applyHeaders(resp.Header, headers)
}

func (e *StarlarkEngine) startWatcher() {
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()

		var lastMod time.Time
		if stat, err := os.Stat(e.scriptPath); err == nil {
			lastMod = stat.ModTime()
		}

		for {
			select {
			case <-e.stopWatch:
				return
			case <-ticker.C:
				if stat, err := os.Stat(e.scriptPath); err == nil {
					if stat.ModTime().After(lastMod) {
						lastMod = stat.ModTime()
						logging.Logger.Info("Script change detected, reloading", zap.String("file", e.scriptPath))
						if err := e.Reload(); err != nil {
							logging.Logger.Error("Script hot-reload failed", zap.Error(err))
						}
					}
				}
			}
		}
	}()
}

func (e *StarlarkEngine) Close() error {
	e.closeOnce.Do(func() { close(e.stopWatch) })
	return nil
}
