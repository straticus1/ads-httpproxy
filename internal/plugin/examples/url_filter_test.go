package examples

import (
	"net/http"
	"net/url"
	"testing"

	"ads-httpproxy/internal/plugin"
)

func TestURLFilterPlugin_DomainMatching(t *testing.T) {
	tests := []struct {
		name         string
		host         string
		domain       string
		shouldMatch  bool
	}{
		{"exact match", "evil.com", "evil.com", true},
		{"subdomain match", "www.evil.com", "evil.com", true},
		{"deep subdomain", "api.v2.evil.com", "evil.com", true},
		{"no partial match", "notevil.com", "evil.com", false},
		{"suffix but not subdomain", "myevil.com", "evil.com", false},
		{"case insensitive", "EVIL.COM", "evil.com", true},
		{"case insensitive subdomain", "WWW.EVIL.COM", "evil.com", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchesDomain(tt.host, tt.domain)
			if got != tt.shouldMatch {
				t.Errorf("matchesDomain(%q, %q) = %v, want %v", tt.host, tt.domain, got, tt.shouldMatch)
			}
		})
	}
}

func TestURLFilterPlugin_OnRequest(t *testing.T) {
	initTestLogger()
	blockedDomains := []string{"evil.com", "malware.net"}
	blockedPatterns := []string{`.*\.exe$`, `.*download.*virus.*`}
	allowedDomains := []string{"trusted.com"}

	p, err := NewURLFilterPlugin(blockedDomains, blockedPatterns, allowedDomains)
	if err != nil {
		t.Fatalf("Failed to create plugin: %v", err)
	}

	tests := []struct {
		name        string
		url         string
		shouldBlock bool
	}{
		{"allowed domain", "https://trusted.com/page", false},
		{"allowed subdomain", "https://api.trusted.com/v1", false},
		{"blocked domain exact", "https://evil.com/page", true},
		{"blocked subdomain", "https://www.evil.com/page", true},
		{"blocked pattern .exe", "https://site.com/file.exe", true},
		{"blocked pattern virus", "https://site.com/download-virus-pack", true},
		{"normal site", "https://google.com/search", false},
		{"not partial match", "https://notevil.com/page", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, _ := url.Parse(tt.url)
			req := &http.Request{
				URL:    u,
				Header: make(http.Header),
			}

			ctx := &plugin.Context{}
			_, resp := p.OnRequest(req, ctx)

			blocked := (resp != nil)
			if blocked != tt.shouldBlock {
				t.Errorf("URL %s: blocked=%v, want %v", tt.url, blocked, tt.shouldBlock)
			}
		})
	}
}

func TestURLFilterPlugin_NilSafety(t *testing.T) {
	p, _ := NewURLFilterPlugin([]string{"evil.com"}, []string{}, []string{})

	tests := []struct {
		name string
		req  *http.Request
	}{
		{"nil request", nil},
		{"nil URL", &http.Request{URL: nil}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &plugin.Context{}
			// Should not panic
			_, resp := p.OnRequest(tt.req, ctx)
			if resp != nil {
				t.Errorf("Expected no response for %s", tt.name)
			}
		})
	}
}
