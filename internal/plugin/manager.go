package plugin

import (
	"net/http"
	"sync"

	"ads-httpproxy/pkg/logging"

	"go.uber.org/zap"
)

type Manager struct {
	plugins []Plugin
	mu      sync.RWMutex
}

func NewManager() *Manager {
	return &Manager{
		plugins: make([]Plugin, 0),
	}
}

func (m *Manager) Register(p Plugin) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.plugins = append(m.plugins, p)
	logging.Logger.Info("Registered plugin", zap.String("name", p.Name()))
}

// HandleRequest executes all plugins' OnRequest
func (m *Manager) HandleRequest(req *http.Request, ctx *Context) (*http.Request, *http.Response) {
	m.mu.RLock()
	defer m.mu.Unlock()

	currentReq := req
	for _, p := range m.plugins {
		modReq, resp := p.OnRequest(currentReq, ctx)
		if resp != nil {
			// Plugin decided to intercept/block
			return nil, resp
		}
		if modReq != nil {
			currentReq = modReq
		}
	}
	return currentReq, nil
}

// HandleResponse executes all plugins' OnResponse
func (m *Manager) HandleResponse(resp *http.Response, ctx *Context) *http.Response {
	m.mu.RLock()
	defer m.mu.Unlock()

	currentResp := resp
	for _, p := range m.plugins {
		modResp := p.OnResponse(currentResp, ctx)
		if modResp != nil {
			currentResp = modResp
		}
	}
	return currentResp
}
