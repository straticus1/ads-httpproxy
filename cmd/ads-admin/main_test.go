package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAPICommands(t *testing.T) {
	for _, tc := range []struct {
		command, path, method string
		args                  []string
	}{{"stats", "/stats", "GET", nil}, {"connections", "/connections", "GET", nil}, {"load", "/plugins/load", "POST", []string{"-path", "example.so"}}, {"reload-plugin", "/plugins/reload", "POST", []string{"-path", "example-v2.so"}}, {"unload", "/plugins/unload", "POST", []string{"-name", "example"}}} {
		t.Run(tc.command, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != tc.path || r.Method != tc.method {
					t.Errorf("request: %s %s", r.Method, r.URL.Path)
				}
				if r.Header.Get("X-API-Key") != "test-key" {
					t.Error("missing API authentication")
				}
				if tc.method == "POST" {
					var payload map[string]string
					if err := json.NewDecoder(r.Body).Decode(&payload); err != nil || len(payload) != 1 {
						t.Errorf("payload: %v, %v", payload, err)
					}
				}
				w.Write([]byte(`{"count":123}`))
			}))
			defer server.Close()
			for _, format := range []string{"json", "yaml", "table"} {
				var out bytes.Buffer
				args := append([]string{tc.command, "-api", server.URL, "-secret", "test-key", "-format", format}, tc.args...)
				if err := run(args, strings.NewReader(""), &out); err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(out.String(), "123") {
					t.Fatalf("output: %s", out.String())
				}
				if format == "yaml" && strings.Contains(out.String(), `"123"`) {
					t.Error("YAML number rendered as string")
				}
			}
		})
	}
}

func TestConfigBatchAndInteractive(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "admin" || pass != "pass" {
			t.Error("missing Basic authentication")
		}
		if r.Header.Get("X-API-Key") != "override" {
			t.Error("explicit flags did not override defaults")
		}
		w.Write([]byte(`{"status":"UP"}`))
	}))
	defer server.Close()
	dir := t.TempDir()
	cfg := filepath.Join(dir, "admin.yaml")
	batch := filepath.Join(dir, "batch.json")
	if err := os.WriteFile(cfg, []byte("api: "+server.URL+"\nsecret: original\nuser: admin\npassword: pass\nformat: yaml\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(batch, []byte(`[["status"],["stats","-format","json"]]`), 0600); err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{"batch", "interactive"} {
		var out bytes.Buffer
		args := []string{command, "-cli-config", cfg, "-secret", "override"}
		if command == "batch" {
			args = append(args, "-file", batch)
		}
		if err := run(args, strings.NewReader("status\nquit\n"), &out); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out.String(), "UP") {
			t.Fatal(out.String())
		}
	}
}

func TestErrors(t *testing.T) {
	for _, args := range [][]string{{"reload"}, {"unknown"}, {"load"}, {"unload"}, {"stats", "-api", ":bad"}, {"stats", "-format", "xml"}, {"stats", "-timeout", "0s"}} {
		if err := run(args, strings.NewReader(""), &bytes.Buffer{}); err == nil {
			t.Fatalf("expected error for %v", args)
		}
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "Unauthorized", 401) }))
	defer server.Close()
	if err := run([]string{"stats", "-api", server.URL}, nil, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("error: %v", err)
	}
}
