package plugin

import (
	"fmt"
	"net/http"
	"reflect"
	"strings"
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

func validatePlugin(p Plugin) error {
	if p == nil {
		return fmt.Errorf("plugin must not be nil")
	}
	value := reflect.ValueOf(p)
	if (value.Kind() == reflect.Pointer || value.Kind() == reflect.Interface) && value.IsNil() {
		return fmt.Errorf("plugin must not be nil")
	}
	if strings.TrimSpace(p.Name()) == "" {
		return fmt.Errorf("plugin must have a name")
	}
	return nil
}

func (m *Manager) Register(p Plugin) error {
	if err := validatePlugin(p); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, current := range m.plugins {
		if current.Name() == p.Name() {
			return fmt.Errorf("plugin already registered: %s", p.Name())
		}
	}
	m.plugins = append(m.plugins, p)
	if logging.Logger != nil {
		logging.Logger.Info("Registered plugin", zap.String("name", p.Name()))
	}
	return nil
}

// Replace atomically swaps an existing plugin. In-flight hooks keep their snapshot.
func (m *Manager) Replace(p Plugin) error {
	if err := validatePlugin(p); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, current := range m.plugins {
		if current.Name() == p.Name() {
			m.plugins[i] = p
			return nil
		}
	}
	return fmt.Errorf("plugin not found: %s", p.Name())
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
			if logging.Logger != nil {
				logging.Logger.Info("Unregistered plugin", zap.String("name", name))
			}
			return nil
		}
	}
	return fmt.Errorf("plugin not found: %s", name)
}

func (m *Manager) snapshot() []Plugin {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]Plugin(nil), m.plugins...)
}

// HandleRequest executes all plugins' OnRequest
func (m *Manager) HandleRequest(req *http.Request, ctx *Context) (*http.Request, *http.Response) {
	plugins := m.snapshot()

	currentReq := req
	for _, p := range plugins {
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
	plugins := m.snapshot()

	currentResp := resp
	for _, p := range plugins {
		modResp := p.OnResponse(currentResp, ctx)
		if modResp != nil {
			currentResp = modResp
		}
	}
	return currentResp
}
