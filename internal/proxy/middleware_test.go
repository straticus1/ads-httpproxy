package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"ads-httpproxy/internal/config"
	"ads-httpproxy/pkg/logging"

	"github.com/elazarl/goproxy"
)

func TestMiddlewareDLP_Request(t *testing.T) {
	// Setup
	logging.Init() // Ensure logger is initialized
	cfg := config.NewConfig()
	// Add a pattern that triggers blocking
	cfg.DlpPatterns = []string{"SECRET_KEY"}
	server := NewServer(cfg)

	// Case 1: Safe Request
	reqSafe := httptest.NewRequest("POST", "http://example.com", strings.NewReader("Safe content"))
	ctx := &goproxy.ProxyCtx{Req: reqSafe}

	reqOut, respOut := server.middlewareDLP(reqSafe, ctx)
	if respOut != nil {
		t.Errorf("Expected nil response (pass-through) for safe content, got %v", respOut)
	}
	if reqOut == nil {
		t.Error("Expected request to be returned")
	}

	// Verify body is readable again
	body, _ := io.ReadAll(reqOut.Body)
	if string(body) != "Safe content" {
		t.Errorf("Expected preserved body 'Safe content', got '%s'", string(body))
	}

	// Case 2: Sensitive content
	reqBad := httptest.NewRequest("POST", "http://example.com", strings.NewReader("Prefix SECRET_KEY Suffix"))
	ctxBad := &goproxy.ProxyCtx{Req: reqBad}

	_, respBlocked := server.middlewareDLP(reqBad, ctxBad)
	if respBlocked == nil {
		t.Error("Expected blocked response for sensitive content")
	} else if respBlocked.StatusCode != http.StatusForbidden {
		t.Errorf("Expected 403 Forbidden, got %d", respBlocked.StatusCode)
	}
}

func TestMiddlewareDLP_Response(t *testing.T) {
	// Setup
	logging.Init()
	cfg := config.NewConfig()
	cfg.DlpPatterns = []string{"SECRET_KEY"}
	server := NewServer(cfg)

	// Case 1: Safe Response
	respSafe := &http.Response{
		StatusCode: 200,
		Body:       io.NopCloser(strings.NewReader("Safe response")),
		Header:     make(http.Header),
	}
	req := httptest.NewRequest("GET", "http://example.com", nil)
	ctx := &goproxy.ProxyCtx{Req: req}

	respOut := server.middlewareRespDLP(respSafe, ctx)
	if respOut.StatusCode != 200 {
		t.Errorf("Expected 200 OK, got %d", respOut.StatusCode)
	}
	body, _ := io.ReadAll(respOut.Body)
	if string(body) != "Safe response" {
		t.Errorf("Expected preserved body, got '%s'", string(body))
	}

	// Case 2: Sensitive Response
	respBad := &http.Response{
		StatusCode: 200,
		Body:       io.NopCloser(strings.NewReader("Data: SECRET_KEY")),
		Header:     make(http.Header),
	}

	respBlocked := server.middlewareRespDLP(respBad, ctx)
	if respBlocked.StatusCode != http.StatusForbidden {
		t.Errorf("Expected 403 Forbidden, got %d", respBlocked.StatusCode)
	}
}
