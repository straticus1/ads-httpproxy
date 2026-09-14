package api

import (
	"ads-httpproxy/internal/config"
	"ads-httpproxy/internal/devtools"
	"ads-httpproxy/internal/plugin"
	"ads-httpproxy/pkg/logging"
	"go.uber.org/zap"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestToolkitAndPACManagementRequireAuthentication(t *testing.T) {
	logging.Logger = zap.NewNop()
	cfg := config.NewConfig()
	cfg.ApiSecret = "test-key"
	server := NewServer(cfg, nil, plugin.NewManager())
	toolkit := devtools.New(&devtools.Config{Enabled: true})
	server.SetDevTools(toolkit)
	handler := server.Handler()
	for _, path := range []string{"/api/devtools/exchanges", "/api/devtools/rules", "/api/pac/policy"} {
		for _, key := range []string{"", "test-key"} {
			req := httptest.NewRequest("GET", path, nil)
			req.Header.Set("X-API-Key", key)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			want := 200
			if key == "" {
				want = 401
			}
			if w.Code != want {
				t.Fatalf("%s with key %q: %d", path, key, w.Code)
			}
		}
	}
	req := httptest.NewRequest("PUT", "/api/devtools/rules", strings.NewReader(`{"rules":[{"host":"example.com","status":200}]}`))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != 401 || len(toolkit.Rules()) != 0 {
		t.Fatal("unauthenticated rules applied")
	}
	disabled := NewServer(cfg, nil, plugin.NewManager()).Handler()
	w = httptest.NewRecorder()
	disabled.ServeHTTP(w, httptest.NewRequest("GET", "/api/devtools/exchanges", nil))
	if w.Code != http.StatusNotFound {
		t.Fatal("disabled toolkit route exposed")
	}
}
