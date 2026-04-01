package examples

import (
	"net/http"
	"testing"

	"ads-httpproxy/internal/plugin"
)

func TestHeaderInjectorPlugin_OnRequest(t *testing.T) {
	reqHeaders := map[string]string{
		"X-Custom-Header": "test-value",
		"X-Company":       "ADS",
	}
	p := NewHeaderInjectorPlugin(reqHeaders, nil)

	tests := []struct {
		name        string
		req         *http.Request
		wantHeaders map[string]string
	}{
		{
			name: "inject headers into valid request",
			req:  &http.Request{Header: make(http.Header)},
			wantHeaders: map[string]string{
				"X-Custom-Header": "test-value",
				"X-Company":       "ADS",
			},
		},
		{
			name:        "nil request",
			req:         nil,
			wantHeaders: nil,
		},
		{
			name:        "request with nil header",
			req:         &http.Request{},
			wantHeaders: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &plugin.Context{}
			modReq, resp := p.OnRequest(tt.req, ctx)

			if resp != nil {
				t.Errorf("OnRequest() returned unexpected response")
			}

			if tt.req != nil && tt.req.Header != nil {
				for key, expectedValue := range tt.wantHeaders {
					if got := modReq.Header.Get(key); got != expectedValue {
						t.Errorf("Header %s = %v, want %v", key, got, expectedValue)
					}
				}
			}
		})
	}
}

func TestHeaderInjectorPlugin_OnResponse(t *testing.T) {
	respHeaders := map[string]string{
		"X-Frame-Options":           "DENY",
		"X-Content-Security-Policy": "default-src 'self'",
	}
	p := NewHeaderInjectorPlugin(nil, respHeaders)

	tests := []struct {
		name        string
		resp        *http.Response
		wantHeaders map[string]string
	}{
		{
			name: "inject headers into valid response",
			resp: &http.Response{Header: make(http.Header)},
			wantHeaders: map[string]string{
				"X-Frame-Options":           "DENY",
				"X-Content-Security-Policy": "default-src 'self'",
			},
		},
		{
			name:        "nil response",
			resp:        nil,
			wantHeaders: nil,
		},
		{
			name:        "response with nil header",
			resp:        &http.Response{},
			wantHeaders: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &plugin.Context{}
			modResp := p.OnResponse(tt.resp, ctx)

			if tt.resp != nil && tt.resp.Header != nil {
				for key, expectedValue := range tt.wantHeaders {
					if got := modResp.Header.Get(key); got != expectedValue {
						t.Errorf("Header %s = %v, want %v", key, got, expectedValue)
					}
				}
			}
		})
	}
}
