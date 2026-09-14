package plugin

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	pluginpkg "plugin"
	"strings"

	"ads-httpproxy/pkg/logging"

	"go.uber.org/zap"
)

// Loader handles loading plugins from shared libraries (.so files)
type Loader struct {
	manager        *Manager
	configurations map[string]json.RawMessage
}

func NewLoader(manager *Manager) *Loader {
	return &Loader{
		manager: manager,
	}
}

func (l *Loader) SetConfigurations(configurations map[string]any) error {
	values := make(map[string]json.RawMessage, len(configurations))
	for name, value := range configurations {
		data, err := json.Marshal(value)
		if err != nil {
			return fmt.Errorf("configuration for %s: %w", name, err)
		}
		values[name] = data
	}
	l.configurations = values
	return nil
}

// LoadFromFile loads a plugin from a .so file
// The .so file must export a "NewPlugin" function that returns a Plugin interface
func (l *Loader) LoadFromFile(path string) error { return l.loadFromFile(path, false) }

// ReloadFromFile replaces an existing plugin only after loading and configuration succeed.
// Go caches shared libraries; new code requires a distinct plugin package path.
func (l *Loader) ReloadFromFile(path string) error { return l.loadFromFile(path, true) }

func (l *Loader) loadFromFile(path string, replace bool) error {
	// Load the plugin shared object
	p, err := pluginpkg.Open(path)
	if err != nil {
		return fmt.Errorf("failed to open plugin %s: %w", path, err)
	}

	// Look for NewPlugin symbol
	newPluginSymbol, err := p.Lookup("NewPlugin")
	if err != nil {
		return fmt.Errorf("plugin %s does not export NewPlugin function: %w", path, err)
	}

	// Assert that it's a function returning a Plugin
	newPlugin, ok := newPluginSymbol.(func() Plugin)
	if !ok {
		return fmt.Errorf("plugin %s NewPlugin function has invalid signature", path)
	}

	// Create plugin instance
	plugin := newPlugin()

	if err := validatePlugin(plugin); err != nil {
		return fmt.Errorf("plugin %s: %w", path, err)
	}
	if versioned, ok := plugin.(interface{ APIVersion() string }); ok && versioned.APIVersion() != "1" {
		return fmt.Errorf("plugin %s uses unsupported API version %s", path, versioned.APIVersion())
	}
	if settings, ok := l.configurations[plugin.Name()]; ok {
		configurable, ok := plugin.(interface{ Configure(json.RawMessage) error })
		if !ok {
			return fmt.Errorf("plugin %s does not support configuration", plugin.Name())
		}
		if err := configurable.Configure(append(json.RawMessage(nil), settings...)); err != nil {
			return fmt.Errorf("configure plugin %s: %w", plugin.Name(), err)
		}
	}
	// Register with manager
	var registerErr error
	if replace {
		registerErr = l.manager.Replace(plugin)
	} else {
		registerErr = l.manager.Register(plugin)
	}
	if registerErr != nil {
		return registerErr
	}

	logging.Logger.Info("Loaded plugin from file",
		zap.String("path", path),
		zap.String("plugin", plugin.Name()))

	return nil
}

// LoadFromDirectory loads all plugins from a directory
func (l *Loader) LoadFromDirectory(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("read plugin directory: %w", err)
	}
	var errs []error
	for _, entry := range entries {
		if !entry.Type().IsRegular() || !strings.HasSuffix(entry.Name(), ".so") {
			continue
		}
		if err := l.LoadFromFile(filepath.Join(dir, entry.Name())); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Example of how to build a plugin .so file:
//
// 1. Create plugin file (e.g., my_plugin.go):
//
// package main
//
// import (
//     "net/http"
//     "ads-httpproxy/pkg/plugin"
// )
//
// type MyPlugin struct{}
//
// func (p *MyPlugin) Name() string { return "my-plugin" }
// func (p *MyPlugin) OnRequest(req *http.Request, ctx *plugin.Context) (*http.Request, *http.Response) {
//     return req, nil
// }
// func (p *MyPlugin) OnResponse(resp *http.Response, ctx *plugin.Context) *http.Response {
//     return resp
// }
//
// func NewPlugin() plugin.Plugin {
//     return &MyPlugin{}
// }
//
// 2. Build as shared library:
//    go build -buildmode=plugin -o my_plugin.so my_plugin.go
//
// 3. Load in proxy:
//    loader.LoadFromFile("/path/to/my_plugin.so")
