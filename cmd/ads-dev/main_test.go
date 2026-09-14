package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRequestThroughProxy(t *testing.T) {
	var visited bool
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		visited = true
		if !r.URL.IsAbs() || r.URL.Host != "example.com" {
			t.Errorf("not forward proxy request: %s", r.URL)
		}
		if r.Header.Get("X-Test") != "yes" {
			t.Error("header missing")
		}
		w.WriteHeader(201)
		w.Write([]byte("abcdef"))
	}))
	defer proxy.Close()
	var output bytes.Buffer
	if err := run([]string{"request", "-url", "http://example.com/test", "-proxy", proxy.URL, "-header", "X-Test: yes", "-max-response-bytes", "3"}, &output); err != nil {
		t.Fatal(err)
	}
	if !visited || !strings.Contains(output.String(), `"body": "abc"`) || !strings.Contains(output.String(), `"truncated": true`) {
		t.Fatal(output.String())
	}
}
func TestCapturesAuthenticated(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-API-Key") != "key" {
			t.Error("missing API key")
		}
		if r.URL.Path != "/api/devtools/exchanges" {
			t.Error(r.URL.Path)
		}
		w.Write([]byte(`{"exchanges":[]}`))
	}))
	defer api.Close()
	if err := run([]string{"captures", "-api", api.URL, "-secret", "key"}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
}
func TestInvalidOptions(t *testing.T) {
	for _, args := range [][]string{{"request"}, {"request", "-url", "https://example.com", "-http3"}, {"replay"}, {"apply-rules"}, {"request", "-url", "ftp://example.com", "-proxy", ""}, {"request", "-timeout", "0s"}} {
		if err := run(args, &bytes.Buffer{}); err == nil {
			t.Fatalf("expected error: %v", args)
		}
	}
}
