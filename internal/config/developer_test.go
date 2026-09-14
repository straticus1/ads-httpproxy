package config

import (
	"ads-httpproxy/internal/devtools"
	"testing"
)

func TestDeveloperConfigurationValidation(t *testing.T) {
	for _, setup := range []func(*Config){
		func(c *Config) { c.EnableQUIC = true },
		func(c *Config) { c.QUICCert = "cert-only" },
		func(c *Config) { c.ParentProxy = "socks5://localhost:1080" },
		func(c *Config) { c.ParentProxy = "http://localhost:8080"; c.QUICUpstreams = []string{"example.com"} },
		func(c *Config) { c.DevTools = &devtools.Config{Enabled: true, Capacity: 10001} },
		func(c *Config) {
			c.DevTools = &devtools.Config{Enabled: true, Rules: []devtools.Rule{{Host: "example.com", DelayMS: 60001}}}
		},
		func(c *Config) { c.QUICRelay = &QUICRelayConfig{Addr: "127.0.0.1:8443", Target: "example.com:0"} },
		func(c *Config) { c.CaCert = "cert-only" },
	} {
		cfg := NewConfig()
		setup(cfg)
		if err := cfg.Validate(); err == nil {
			t.Fatalf("invalid config accepted: %+v", cfg)
		}
	}
	cfg := NewConfig()
	cfg.QUICRelay = &QUICRelayConfig{Addr: "127.0.0.1:8443", Target: "example.com:443"}
	cfg.DevTools = &devtools.Config{Enabled: true}
	cfg.ParentProxy = "http://localhost:8080"
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
}
