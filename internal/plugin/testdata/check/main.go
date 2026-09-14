package main

import (
	"ads-httpproxy/internal/plugin"
	"ads-httpproxy/pkg/logging"
	"fmt"
	"go.uber.org/zap"
	"net/http"
	"os"
)

func main() {
	logging.Logger = zap.NewNop()
	manager := plugin.NewManager()
	loader := plugin.NewLoader(manager)
	check := func(err error) {
		if err != nil {
			panic(err)
		}
	}
	check(loader.SetConfigurations(map[string]any{"integration-plugin": map[string]any{"Value": "configured"}}))
	check(loader.LoadFromFile(os.Args[1]))
	verify := func(want string) {
		req, _ := http.NewRequest("GET", "http://example.com", nil)
		req, _ = manager.HandleRequest(req, nil)
		if req.Header.Get("X-Plugin") != want {
			panic("incorrect plugin/configuration: " + req.Header.Get("X-Plugin"))
		}
	}
	verify("one:configured")
	check(loader.ReloadFromFile(os.Args[2]))
	verify("two:configured")
	if err := loader.ReloadFromFile(os.Args[3]); err == nil {
		panic("incompatible API accepted")
	}
	verify("two:configured")
	if err := loader.LoadFromFile(os.Args[2]); err == nil {
		panic("duplicate registration accepted")
	}
	check(manager.Remove("integration-plugin"))
	fmt.Println("Shared plugin loading, settings, hot replacement, and API compatibility passed")
}
