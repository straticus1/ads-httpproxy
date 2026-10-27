package config

import (
	"ads-httpproxy/internal/access"
	"ads-httpproxy/internal/adaptive"
	"ads-httpproxy/internal/ai"
	"ads-httpproxy/internal/analysis"
	"ads-httpproxy/internal/headerpolicy"
	"fmt"
)

type GatewayTLSConfig struct {
	Cert     string `json:"cert" yaml:"cert"`
	Key      string `json:"key" yaml:"key"`
	ClientCA string `json:"client_ca" yaml:"client_ca"`
}

func (c *Config) validatePlatform() error {
	if err := headerpolicy.Validate(c.Headers); err != nil {
		return err
	}
	if len(c.APIKeys) > 0 && c.ApiSecret == "changeme" {
		return fmt.Errorf("replace or clear default api_secret before enabling scoped keys")
	}
	if c.ConnectMode != "" && c.ConnectMode != "mitm" && c.ConnectMode != "tunnel" {
		return fmt.Errorf("connect_mode must be mitm or tunnel")
	}
	if c.ControlPlane != nil {
		if err := c.ControlPlane.Validate(); err != nil {
			return err
		}
	}
	if err := validateAPIKeys(c.APIKeys); err != nil {
		return err
	}
	if c.Analysis != nil {
		if err := analysis.Validate(*c.Analysis); err != nil {
			return err
		}
	}
	if c.Adaptive != nil {
		if err := adaptive.Validate(*c.Adaptive); err != nil {
			return err
		}
	}
	if c.AI != nil {
		if err := ai.Validate(*c.AI); err != nil {
			return err
		}
	}
	if err := ValidateIdentity(c.Auth); err != nil {
		return err
	}
	if c.Access != nil {
		if err := access.Validate(*c.Access); err != nil {
			return err
		}
	}
	if c.Auth != nil && c.Auth.Mechanism == "mtls" && (c.GatewayTLS == nil || c.GatewayTLS.ClientCA == "") {
		return fmt.Errorf("mtls authentication requires gateway_tls.client_ca")
	}
	if c.Access != nil && c.Access.Enabled && c.Access.RequireMTLS && (c.GatewayTLS == nil || c.GatewayTLS.ClientCA == "") {
		return fmt.Errorf("access require_mtls needs gateway_tls.client_ca")
	}
	for _, app := range c.Apps {
		if app != nil {
			for _, r := range app.Routes {
				if r.RateLimit < 0 {
					return fmt.Errorf("app route rate_limit cannot be negative")
				}
			}
		}
	}
	if c.GatewayTLS != nil && (c.GatewayTLS.Cert == "" || c.GatewayTLS.Key == "") {
		return fmt.Errorf("gateway_tls requires cert and key")
	}
	for _, r := range c.Routes {
		if r.RateLimit < 0 {
			return fmt.Errorf("route rate_limit cannot be negative")
		}
	}
	return nil
}
