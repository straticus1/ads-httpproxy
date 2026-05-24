package plugin

import (
	"fmt"
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

func (m *Manager) List() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	names := make([]string, len(m.plugins))
	for i, p := range m.plugins {
		names[i] = p.Name()
	}
	return names
}

func (m *Manager) Remove(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, p := range m.plugins {
		if p.Name() == name {
			// Remove from slice
			m.plugins = append(m.plugins[:i], m.plugins[i+1:]...)
			logging.Logger.Info("Unregistered plugin", zap.String("name", name))
			return nil
		}
	}
	return fmt.Errorf("plugin not found: %s", name)
}

// HandleRequest executes all plugins' OnRequest
func (m *Manager) HandleRequest(req *http.Request, ctx *Context) (*http.Request, *http.Response) {
	m.mu.RLock()
	defer m.mu.RUnlock()

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
	defer m.mu.RUnlock()

	currentResp := resp
	for _, p := range m.plugins {
		modResp := p.OnResponse(currentResp, ctx)
		if modResp != nil {
			currentResp = modResp
		}
	}
	return currentResp
}
