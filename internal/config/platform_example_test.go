package config

import "testing"

func TestPlatformExampleWithEnvironmentSecret(t *testing.T) {
	t.Setenv("ADS_API_SECRET", "example-test-secret")
	cfg, err := Load("../../examples/platform.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ApiSecret != "example-test-secret" || cfg.Analysis == nil || !cfg.Analysis.Enabled || cfg.Adaptive.Mode != "shadow" {
		t.Fatal("platform example did not load expected secret and opt-in controls")
	}
}
