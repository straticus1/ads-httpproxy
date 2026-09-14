package proxy

import (
	"ads-httpproxy/internal/config"
	"ads-httpproxy/internal/devtools"
	"ads-httpproxy/pkg/logging"
	"context"
	"go.uber.org/zap"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestForwardProxyToolkitAndScriptHooks(t *testing.T) {
	logging.Logger = zap.NewNop()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Script") != "request" {
			t.Error("request script not called")
		}
		w.Header().Set("Content-Type", "text/plain")
		io.WriteString(w, "real response")
	}))
	defer upstream.Close()
	path := filepath.Join(t.TempDir(), "policy.star")
	script := `def on_request(req):
    req.headers["X-Script"] = "request"
    return False
def on_response(resp):
    resp.headers["X-Script"] = "response"
    return False
`
	if err := os.WriteFile(path, []byte(script), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := config.NewConfig()
	cfg.Auth.AllowUnauthenticated = true
	cfg.Auth.AllowedSourceNets = []string{"127.0.0.0/8"}
	cfg.ScriptFile = path
	cfg.DevTools = &devtools.Config{Enabled: true, CaptureBodies: true}
	s := NewServer(cfg)
	defer s.Shutdown(context.Background())
	server := httptest.NewServer(http.HandlerFunc(s.GatewayHandler))
	defer server.Close()
	proxyURL, _ := url.Parse(server.URL)
	tr := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	resp, err := client.Get(upstream.URL + "/test")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "real response" || resp.Header.Get("X-Script") != "response" {
		t.Fatal("response script or forwarding failed")
	}
	entries := s.devtools.List()
	if len(entries) != 1 || entries[0].ResponseBody != "real response" {
		t.Fatalf("capture: %+v", entries)
	}
	target, _ := url.Parse(upstream.URL)
	if err := s.devtools.SetRules([]devtools.Rule{{Host: target.Host, Status: 202, Body: "mock"}}); err != nil {
		t.Fatal(err)
	}
	resp, err = client.Get(upstream.URL + "/mock")
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 202 || string(body) != "mock" {
		t.Fatal("mock not applied")
	}
}
func TestParentProxyUsesAbsoluteRequestAndCredentials(t *testing.T) {
	logging.Logger = zap.NewNop()
	called := false
	parent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		if r.URL.String() != "http://unreachable.invalid/path" {
			t.Error(r.URL.String())
		}
		if !strings.HasPrefix(r.Header.Get("Proxy-Authorization"), "Basic ") {
			t.Error("parent credentials missing")
		}
		io.WriteString(w, "parent response")
	}))
	defer parent.Close()
	u, _ := url.Parse(parent.URL)
	u.User = url.UserPassword("parent-user", "parent-password")
	cfg := config.NewConfig()
	cfg.ParentProxy = u.String()
	cfg.Auth.AllowUnauthenticated = true
	cfg.Auth.AllowedSourceNets = []string{"127.0.0.0/8"}
	s := NewServer(cfg)
	defer s.Shutdown(context.Background())
	server := httptest.NewServer(http.HandlerFunc(s.GatewayHandler))
	defer server.Close()
	proxyURL, _ := url.Parse(server.URL)
	tr := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	defer tr.CloseIdleConnections()
	resp, err := (&http.Client{Transport: tr, Timeout: 5 * time.Second}).Get("http://unreachable.invalid/path")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if !called || string(body) != "parent response" {
		t.Fatal("request bypassed parent")
	}
}

func TestForwardProxyRejectsUntrustedUpstreamTLS(t *testing.T) {
	logging.Logger = zap.NewNop()
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("untrusted TLS upstream was reached") }))
	defer upstream.Close()
	cfg := config.NewConfig()
	s := NewServer(cfg)
	defer s.Shutdown(context.Background())
	req, _ := http.NewRequest("GET", upstream.URL, nil)
	if response, err := s.proxy.Tr.RoundTrip(req); err == nil {
		if response != nil {
			response.Body.Close()
		}
		t.Fatal("untrusted upstream certificate accepted")
	}
}
