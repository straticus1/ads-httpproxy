package examples

import (
	"net/http"
	"testing"
	"time"

	"ads-httpproxy/internal/plugin"
)

func TestRateLimiterPlugin_BasicLimiting(t *testing.T) {
	initTestLogger()
	p := NewRateLimiterPlugin(3, 1*time.Minute)
	defer p.Shutdown()

	req := &http.Request{
		RemoteAddr: "192.168.1.100:12345",
		Header:     make(http.Header),
	}
	ctx := &plugin.Context{}

	// First 3 requests should succeed
	for i := 0; i < 3; i++ {
		_, resp := p.OnRequest(req, ctx)
		if resp != nil {
			t.Errorf("Request %d should succeed but was blocked", i+1)
		}
	}

	// 4th request should be blocked
	_, resp := p.OnRequest(req, ctx)
	if resp == nil {
		t.Error("Request 4 should be blocked but was allowed")
	}
	if resp != nil && resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("Expected status 429, got %d", resp.StatusCode)
	}
}

func TestRateLimiterPlugin_IPExtraction(t *testing.T) {
	initTestLogger()
	p := NewRateLimiterPlugin(100, 1*time.Minute)
	defer p.Shutdown()

	tests := []struct {
		name       string
		remoteAddr string
		xff        string
		wantAllow  bool
	}{
		{"IP with port", "192.168.1.100:54321", "", true},
		{"IP without port", "192.168.1.100", "", true},
		{"X-Forwarded-For single", "10.0.0.1:12345", "203.0.113.1", true},
		{"X-Forwarded-For chain", "10.0.0.1:12345", "203.0.113.1, 192.168.1.1", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &http.Request{
				RemoteAddr: tt.remoteAddr,
				Header:     make(http.Header),
			}
			if tt.xff != "" {
				req.Header.Set("X-Forwarded-For", tt.xff)
			}

			ctx := &plugin.Context{}
			_, resp := p.OnRequest(req, ctx)
			allowed := (resp == nil)

			if allowed != tt.wantAllow {
				t.Errorf("Request allowed=%v, want %v", allowed, tt.wantAllow)
			}
		})
	}
}

func TestRateLimiterPlugin_WindowExpiration(t *testing.T) {
	initTestLogger()
	p := NewRateLimiterPlugin(2, 100*time.Millisecond)
	defer p.Shutdown()

	req := &http.Request{
		RemoteAddr: "192.168.1.200:12345",
		Header:     make(http.Header),
	}
	ctx := &plugin.Context{}

	// Use up the limit
	_, resp1 := p.OnRequest(req, ctx)
	_, resp2 := p.OnRequest(req, ctx)
	if resp1 != nil || resp2 != nil {
		t.Fatal("First 2 requests should succeed")
	}

	// 3rd should be blocked
	_, resp3 := p.OnRequest(req, ctx)
	if resp3 == nil {
		t.Error("3rd request should be blocked")
	}

	// Wait for window to expire
	time.Sleep(150 * time.Millisecond)

	// Should be allowed again
	_, resp4 := p.OnRequest(req, ctx)
	if resp4 != nil {
		t.Error("Request after window expiration should succeed")
	}
}

func TestRateLimiterPlugin_NilSafety(t *testing.T) {
	p := NewRateLimiterPlugin(100, 1*time.Minute)
	defer p.Shutdown()

	ctx := &plugin.Context{}
	_, resp := p.OnRequest(nil, ctx)
	if resp != nil {
		t.Error("Nil request should not cause a block")
	}
}

func TestRateLimiterPlugin_DefaultValues(t *testing.T) {
	tests := []struct {
		name        string
		maxRequests int
		window      time.Duration
	}{
		{"zero max requests", 0, 1 * time.Minute},
		{"negative max requests", -10, 1 * time.Minute},
		{"zero window", 100, 0},
		{"negative window", 100, -1 * time.Minute},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewRateLimiterPlugin(tt.maxRequests, tt.window)
			defer p.Shutdown()

			// Should use defaults and not panic
			if p.MaxRequests <= 0 {
				t.Error("MaxRequests should have default value")
			}
			if p.Window <= 0 {
				t.Error("Window should have default value")
			}
		})
	}
}

func TestRateLimiterPlugin_Shutdown(t *testing.T) {
	p := NewRateLimiterPlugin(100, 1*time.Minute)

	// Shutdown should complete without hanging
	done := make(chan struct{})
	go func() {
		p.Shutdown()
		close(done)
	}()

	select {
	case <-done:
		// Success
	case <-time.After(2 * time.Second):
		t.Fatal("Shutdown hung")
	}
}
