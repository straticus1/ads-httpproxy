package tengo

import (
	"context"
	"io/ioutil"
	"net/http"
	"sync"

	"ads-httpproxy/pkg/logging"

	"github.com/d5/tengo/v2"
	"github.com/d5/tengo/v2/stdlib"
	"go.uber.org/zap"
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

	// Pre-define variables to ensure compilation passes if script uses them
	// Actually, Tengo requires variables to be defined in scope or passed.
	// We will assume the script expects 'req' or 'resp' to be defined.
	// Compilation might fail if we don't declare them?
	// No, Embedder can add them at runtime, but compilation checks variable existence.
	// For now, we just compile.

	compiled, err := script.Compile()
	if err != nil {
		return err
	}
	e.compiled = compiled
	return nil
}

func (e *TengoEngine) OnRequest(ctx context.Context, req *http.Request) error {
	e.mu.RLock()
	compiled := e.compiled
	e.mu.RUnlock()

	if compiled == nil {
		return nil // No script loaded
	}

	// Prepare data
	reqMap := map[string]interface{}{
		"method": req.Method,
		"url":    req.URL.String(),
		"host":   req.Host,
		"remote": req.RemoteAddr,
	}

	if err := compiled.RunContext(ctx); err != nil {
		logging.Logger.Error("Script run failed", zap.Error(err))
		return nil // Don't block on script error?
	}

	// Ideally we pass 'req' as a variable.
	// compiled.Run() runs the compiled bytecode. We need to set variables.
	// Tengo Compiled object is reusable but not concurrent safe for setting variables if cloned?
	// We need to clone it.

	executable := compiled.Clone()
	executable.Set("req", reqMap)

	if err := executable.RunContext(ctx); err != nil {
		logging.Logger.Error("Script execution failed", zap.Error(err))
		return err // Or return nil
	}

	// Check results?
	// E.g. check if script set "block" variable.
	if block := executable.Get("block"); block != nil && block.Bool() {
		return context.Canceled // or custom error
	}

	return nil
}

func (e *TengoEngine) OnResponse(ctx context.Context, resp *http.Response) error {
	return nil
}
