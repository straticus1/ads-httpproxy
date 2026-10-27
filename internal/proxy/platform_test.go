package proxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"ads-httpproxy/internal/access"
	"ads-httpproxy/internal/adaptive"
	"ads-httpproxy/internal/analysis"
	"ads-httpproxy/internal/auth"
	"ads-httpproxy/internal/config"
	"ads-httpproxy/pkg/logging"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func platformProxy(t *testing.T, cfg *config.Config) (*Server, *http.Client, string) {
	t.Helper()
	logging.Logger = zap.NewNop()
	cfg.Auth.AllowUnauthenticated = true
	s := NewServer(cfg)
	require.NoError(t, s.initErr)
	t.Cleanup(func() { require.NoError(t, s.Shutdown(context.Background())) })
	listener := httptest.NewServer(http.HandlerFunc(s.GatewayHandler))
	t.Cleanup(listener.Close)
	proxyURL, err := url.Parse(listener.URL)
	require.NoError(t, err)
	tr := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	t.Cleanup(tr.CloseIdleConnections)
	return s, &http.Client{Transport: tr, Timeout: 5 * time.Second}, listener.URL
}

func platformRequest(t *testing.T, client *http.Client, method, target string, headers http.Header) (int, http.Header, string) {
	t.Helper()
	req, err := http.NewRequest(method, target, nil)
	require.NoError(t, err)
	if headers != nil {
		req.Header = headers.Clone()
	}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, resp.Header, string(body)
}

type countingByteLimiter struct{ requests atomic.Int32 }

func (l *countingByteLimiter) WaitN(_ context.Context, n int) error {
	if n > 0 {
		l.requests.Add(1)
	}
	return nil
}

func TestPlatformRouteLimitIsIndependentOfBandwidth(t *testing.T) {
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { calls.Add(1); io.WriteString(w, "ok") }))
	t.Cleanup(upstream.Close)
	cfg := config.NewConfig()
	cfg.BandwidthLimit = 0
	cfg.Routes = []config.RouteConfig{{Path: "/limited", Upstream: upstream.URL, RateLimit: 1}, {Path: "/unlimited", Upstream: upstream.URL}}
	s, _, gateway := platformProxy(t, cfg)
	bytes := &countingByteLimiter{}
	s.limiter = bytes
	client := &http.Client{Timeout: 5 * time.Second}
	code, _, _ := platformRequest(t, client, "GET", gateway+"/limited", nil)
	require.Equal(t, 200, code)
	// Freeze replenishment after the configured burst to make the test independent
	// of wall-clock scheduling while exercising the real HTTP handler.
	s.compiledRoutes[0].RequestLimiter.SetLimit(0)
	code, header, _ := platformRequest(t, client, "GET", gateway+"/limited", nil)
	require.Equal(t, 429, code)
	require.Equal(t, "1", header.Get("Retry-After"))
	code, _, _ = platformRequest(t, client, "GET", gateway+"/unlimited", nil)
	require.Equal(t, 200, code)
	require.EqualValues(t, 2, calls.Load())
	require.Zero(t, bytes.requests.Load(), "request limiting must not consume bandwidth tokens")
}

func TestPlatformProxyWriteInvalidatesCachedVariants(t *testing.T) {
	var generation, reads atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		if r.Method == "POST" {
			generation.Add(1)
			w.WriteHeader(204)
			return
		}
		reads.Add(1)
		if generation.Load() == 0 {
			io.WriteString(w, strings.Repeat("old", 512))
		} else {
			io.WriteString(w, strings.Repeat("new", 512))
		}
	}))
	t.Cleanup(upstream.Close)
	cfg := config.NewConfig()
	cfg.Cache = &config.HTTPCacheConfig{Enabled: true, Memory: &config.MemoryCacheConfig{Enabled: true, MaxSizeMB: 2, MaxTTL: 60}}
	s, client, _ := platformProxy(t, cfg)
	s.proxy.KeepAcceptEncoding = true
	for _, encoding := range []string{"identity", "gzip"} {
		for _, want := range []string{"MISS", "HIT"} {
			code, h, body := platformRequest(t, client, "GET", upstream.URL+"/item", http.Header{"Accept-Encoding": {encoding}})
			require.Equal(t, 200, code)
			require.Equal(t, want, h.Get("X-Cache"))
			require.Equal(t, strings.Repeat("old", 512), body)
		}
	}
	code, _, _ := platformRequest(t, client, "POST", upstream.URL+"/item", nil)
	require.Equal(t, 204, code)
	for _, encoding := range []string{"identity", "gzip"} {
		code, h, body := platformRequest(t, client, "GET", upstream.URL+"/item", http.Header{"Accept-Encoding": {encoding}})
		require.Equal(t, 200, code)
		require.Equal(t, "MISS", h.Get("X-Cache"))
		require.Equal(t, strings.Repeat("new", 512), body)
	}
	require.EqualValues(t, 4, reads.Load())
}

type platformAuthenticator struct{ principal auth.Principal }

func (a platformAuthenticator) Challenge(*http.Request) (string, error) { return "", nil }
func (a platformAuthenticator) Authenticate(r *http.Request) (bool, string, string, error) {
	auth.BindPrincipal(r, a.principal)
	return true, a.principal.Username, "", nil
}

func TestPlatformIdentityCannotBeSpoofedAndWorkersCaptureTraffic(t *testing.T) {
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("X-Tenant-ID") != "" || r.Header.Get("X-Authenticated-User") != "" {
			t.Errorf("untrusted identity forwarded: %v", r.Header)
		}
		for _, name := range []string{"X-Authenticated-Groups", "X-Groups", "X-Authenticated-Tenant", "X-Authenticated-Scopes"} {
			if r.Header.Get(name) != "" {
				t.Errorf("untrusted %s forwarded upstream", name)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"ok":true}`)
	}))
	t.Cleanup(upstream.Close)
	cfg := config.NewConfig()
	cfg.Analysis = &analysis.Config{Enabled: true, Workers: 1}
	cfg.Access = &access.Config{Enabled: true, DefaultEffect: "allow", RequiredGroups: []string{"finance"}}
	s, client, _ := platformProxy(t, cfg)
	spoof := http.Header{"X-Tenant-Id": {"other-tenant"}, "X-Authenticated-User": {"admin"}, "X-Authenticated-Groups": {"finance"}, "X-Groups": {"finance"}, "X-Authenticated-Tenant": {"other-tenant"}, "X-Authenticated-Scopes": {"admin"}}
	code, _, _ := platformRequest(t, client, "GET", upstream.URL+"/first", spoof)
	require.Equal(t, 403, code)
	require.Zero(t, calls.Load())
	// Install a verified identity at the authenticator boundary, not as a header.
	s.authenticator = platformAuthenticator{principal: auth.Principal{Subject: "subject-1", Username: "alice", Tenant: "verified-tenant", Groups: []string{"finance"}, Issuer: "test-issuer"}}
	code, _, _ = platformRequest(t, client, "GET", upstream.URL+"/second?token=hidden", spoof)
	require.Equal(t, 200, code)
	require.Eventually(t, func() bool {
		return len(s.analysis.Snapshot(analysis.Filter{Tenant: "verified-tenant", Category: "api"})) == 1
	}, time.Second, 10*time.Millisecond)
	finding := s.analysis.Snapshot(analysis.Filter{Tenant: "verified-tenant", Category: "api"})[0]
	require.Equal(t, "subject-1", finding.Subject)
	require.NotContains(t, finding.URL, "hidden")
	require.Empty(t, s.analysis.Snapshot(analysis.Filter{Tenant: "other-tenant"}))
}

func TestPlatformAdaptiveShadowThenEnforceThroughHTTP(t *testing.T) {
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { calls.Add(1); io.WriteString(w, "origin") }))
	t.Cleanup(upstream.Close)
	u, err := url.Parse(upstream.URL)
	require.NoError(t, err)
	cfg := config.NewConfig()
	cfg.Analysis = &analysis.Config{Enabled: true, Workers: 1}
	cfg.Adaptive = &adaptive.Config{Enabled: true, Mode: "shadow", Rules: []adaptive.Rule{{ID: "block-private", Host: u.Host, PathPrefix: "/private", Action: "block"}}}
	s, client, _ := platformProxy(t, cfg)
	code, h, body := platformRequest(t, client, "GET", upstream.URL+"/private", nil)
	require.Equal(t, 200, code)
	require.Equal(t, "origin", body)
	require.Equal(t, "shadow-block", h.Get("X-ADS-Adaptive"))
	snap := s.adaptive.Snapshot()
	_, err = s.adaptive.Replace(snap.Version, "enforce", snap.Rules)
	require.NoError(t, err)
	code, _, body = platformRequest(t, client, "GET", upstream.URL+"/private", nil)
	require.Equal(t, 403, code)
	require.Contains(t, body, "block-private")
	require.EqualValues(t, 1, calls.Load())
	require.Eventually(t, func() bool { return len(s.analysis.Snapshot(analysis.Filter{Category: "policy_block"})) == 1 }, time.Second, 10*time.Millisecond)
	current := s.adaptive.Snapshot()
	_, err = s.adaptive.Rollback(current.Version, snap.Version)
	require.NoError(t, err)
	code, h, _ = platformRequest(t, client, "GET", upstream.URL+"/private", nil)
	require.Equal(t, 200, code)
	require.Equal(t, "shadow-block", h.Get("X-ADS-Adaptive"))
}
