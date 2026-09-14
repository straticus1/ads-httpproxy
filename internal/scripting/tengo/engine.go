package tengo

import (
	"context"
	"io/ioutil"
	"net/http"
	"sync"

	"github.com/d5/tengo/v2"
	"github.com/d5/tengo/v2/stdlib"
)

type TengoEngine struct {
	scriptPath string
	compiled   *tengo.Compiled
	mu         sync.RWMutex
}

func NewEngine(scriptPath string) (*TengoEngine, error) {
	e := &TengoEngine{scriptPath: scriptPath}
	if err := e.Reload(); err != nil {
		return nil, err
	}
	return e, nil
}

func (e *TengoEngine) Name() string {
	return "tengo"
}

func (e *TengoEngine) Reload() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	content, err := ioutil.ReadFile(e.scriptPath)
	if err != nil {
		return err
	}

	script := tengo.NewScript(content)
	script.SetImports(stdlib.GetModuleMap(stdlib.AllModuleNames()...))

	if err := script.Add("req", map[string]interface{}{}); err != nil {
		return err
	}
	if err := script.Add("resp", map[string]interface{}{}); err != nil {
		return err
	}
	if err := script.Add("phase", "request"); err != nil {
		return err
	}

	compiled, err := script.Compile()
	if err != nil {
		return err
	}
	e.compiled = compiled
	return nil
}

func (e *TengoEngine) execute(ctx context.Context, phase string, req *http.Request, resp *http.Response) error {
	e.mu.RLock()
	compiled := e.compiled
	e.mu.RUnlock()
	if compiled == nil {
		return nil
	}
	executable := compiled.Clone()
	reqMap := map[string]interface{}{"method": "", "url": "", "host": "", "remote": ""}
	if req != nil {
		reqMap = map[string]interface{}{"method": req.Method, "url": req.URL.String(), "host": req.Host, "remote": req.RemoteAddr}
	}
	respMap := map[string]interface{}{"status_code": 0}
	if resp != nil {
		respMap["status_code"] = resp.StatusCode
	}
	for name, value := range map[string]interface{}{"req": reqMap, "resp": respMap, "phase": phase} {
		if err := executable.Set(name, value); err != nil {
			return err
		}
	}
	if err := executable.RunContext(ctx); err != nil {
		return err
	}
	if block := executable.Get("block"); block != nil && block.Bool() {
		return context.Canceled
	}
	return nil
}
func (e *TengoEngine) OnRequest(ctx context.Context, req *http.Request) error {
	return e.execute(ctx, "request", req, nil)
}
func (e *TengoEngine) OnResponse(ctx context.Context, resp *http.Response) error {
	if resp == nil {
		return nil
	}
	return e.execute(ctx, "response", resp.Request, resp)
}

func (e *TengoEngine) Close() error {
	return nil
}
