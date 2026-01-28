package config

import (
	"os"
	"testing"
)

func TestLoadConfig(t *testing.T) {
	// Test JSON
	jsonConfig := `{
		"addr": ":8081",
		"auth": {
			"mechanism": "kerberos",
			"krb5_keytab": "/tmp/test.keytab"
		}
	}`
	jsonFile, _ := os.CreateTemp("", "config_test_*.json")
	defer os.Remove(jsonFile.Name())
	jsonFile.WriteString(jsonConfig)
	jsonFile.Close()

	cfg, err := Load(jsonFile.Name())
	if err != nil {
		t.Fatalf("Failed to load JSON config: %v", err)
	}
	if cfg.Addr != ":8081" {
		t.Errorf("Expected addr :8081, got %s", cfg.Addr)
	}
	if cfg.Auth.Mechanism != "kerberos" {
		t.Errorf("Expected mechanism kerberos, got %s", cfg.Auth.Mechanism)
	}

	// Test YAML
	yamlConfig := `
addr: ":8082"
auth:
  mechanism: "ntlm"
  users:
    user: pass
`
	yamlFile, _ := os.CreateTemp("", "config_test_*.yaml")
	defer os.Remove(yamlFile.Name())
	yamlFile.WriteString(yamlConfig)
	yamlFile.Close()

	cfg, err = Load(yamlFile.Name())
	if err != nil {
		t.Fatalf("Failed to load YAML config: %v", err)
	}
	if cfg.Addr != ":8082" {
		t.Errorf("Expected addr :8082, got %s", cfg.Addr)
	}

	// Test Validation Failure
	badConfig := `{"addr": ""}`
	badFile, _ := os.CreateTemp("", "config_bad_*.json")
	defer os.Remove(badFile.Name())
	badFile.WriteString(badConfig)
	badFile.Close()

	_, err = Load(badFile.Name())
	if err == nil {
		t.Error("Expected validation error for empty addr, got nil")
	}
}
