package plugin

import (
	"fmt"
	pluginpkg "plugin"

	"ads-httpproxy/pkg/logging"

	"go.uber.org/zap"
)

// Loader handles loading plugins from shared libraries (.so files)
type Loader struct {
	manager *Manager
}

func NewLoader(manager *Manager) *Loader {
	return &Loader{
		manager: manager,
	}
}

// LoadFromFile loads a plugin from a .so file
// The .so file must export a "NewPlugin" function that returns a Plugin interface
func (l *Loader) LoadFromFile(path string) error {
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

	// Register with manager
	l.manager.Register(plugin)

	logging.Logger.Info("Loaded plugin from file",
		zap.String("path", path),
		zap.String("plugin", plugin.Name()))

	return nil
}

// LoadFromDirectory loads all plugins from a directory
func (l *Loader) LoadFromDirectory(dir string) error {
	// This would scan directory for .so files and load each one
	// Implementation depends on how you want to structure plugin distribution
	logging.Logger.Info("Plugin directory loading not yet implemented",
		zap.String("directory", dir))
	return nil
}

// Example of how to build a plugin .so file:
//
// 1. Create plugin file (e.g., my_plugin.go):
//
// package main
//
// import (
//     "net/http"
//     "ads-httpproxy/internal/plugin"
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
