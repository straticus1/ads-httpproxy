package config

import (
	"strings"
	"testing"
)

func TestScopedKeysRejectDefaultAdministratorSecret(t *testing.T) {
	c := NewConfig()
	c.APIKeys = []ScopedAPIKey{{ID: "a", Tenant: "a", SHA256: strings.Repeat("ab", 32), Scopes: []string{"findings:read"}}}
	if err := c.validatePlatform(); err == nil {
		t.Fatal("default administrator secret would bypass tenant scopes")
	}
	c.ApiSecret = ""
	if err := c.validatePlatform(); err != nil {
		t.Fatal(err)
	}
	c.APIKeys[0].Scopes = []string{"admin"}
	if err := c.validatePlatform(); err == nil {
		t.Fatal("unexpected global scope")
	}
}
