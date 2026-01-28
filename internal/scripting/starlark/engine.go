package starlark

import (
	"context"
	"fmt"
	"net/http"
	"sync"

	"ads-httpproxy/pkg/logging"

	"go.starlark.net/starlark"
	"go.starlark.net/starlarkstruct"
	"go.uber.org/zap"
)

type StarlarkEngine struct {
	scriptPath string
	mu         sync.RWMutex
	program    *starlark.Program
	globals    starlark.StringDict
}

func NewEngine(scriptPath string) (*StarlarkEngine, error) {
	e := &StarlarkEngine{scriptPath: scriptPath}
	if err := e.Reload(); err != nil {
		return nil, err
	}
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
	globals, err := starlark.ExecFile(thread, e.scriptPath, nil, nil)
	if err != nil {
		return fmt.Errorf("starlark exec error: %w", err)
	}

	e.globals = globals
	// Note: We aren't pre-compiling a function here, we are just executing the file config.
	// Actually, for per-request logic, usually you want a function `on_request(req)` defined in the script,
	// OR we just re-execute the script with inputs?
	// Re-executing is slower. Better to call a function.
	// Let's assume the script defines `on_request(req)`.

	if _, ok := globals["on_request"]; !ok {
		// Fallback: If no function, maybe we just re-exec?
		// For policy simple scripts, re-exec with injected globals is common but requires re-parsing?
		// No, Starlark doesn't support injecting globals into ExecFile easily without Predeclared.
		// So we must use Predeclared.
		// But ExecFile parses and runs.
		// Let's enforce function-based approach: `def on_request(req): ... return block`
		// This is much more efficient and cleaner.
		// However, the user might want simple top-level code.
		// Let's look for `on_request`.
		return fmt.Errorf("script must define 'on_request(req)' function")
	}

	return nil
}

func (e *StarlarkEngine) OnRequest(ctx context.Context, req *http.Request) error {
	e.mu.RLock()
	globals := e.globals
	e.mu.RUnlock()

	if globals == nil {
		return nil
	}

	onRequest, ok := globals["on_request"]
	if !ok {
		return nil
	}

	// Build 'req' object
	reqData := starlarkstruct.FromStringDict(starlark.String("request"), starlark.StringDict{
		"method": starlark.String(req.Method),
		"url":    starlark.String(req.URL.String()),
		"host":   starlark.String(req.Host),
		"remote": starlark.String(req.RemoteAddr),
	})

	thread := &starlark.Thread{Name: "request"}
	// Call on_request(req)
	val, err := starlark.Call(thread, onRequest, starlark.Tuple{reqData}, nil)
	if err != nil {
		logging.Logger.Error("Starlark execution failed", zap.Error(err))
		return nil // Don't fail open? Or fail closed?
	}

	// Check return value
	// Expected: True (block) or False (allow) or Dict
	if val.Truth() {
		return context.Canceled // Block
	}

	return nil
}

func (e *StarlarkEngine) OnResponse(ctx context.Context, resp *http.Response) error {
	return nil
}
