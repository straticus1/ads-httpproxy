package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"ads-httpproxy/internal/adaptive"
	"ads-httpproxy/internal/auth"
	"ads-httpproxy/internal/cache"
	"ads-httpproxy/pkg/logging"
	"github.com/elazarl/goproxy"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

type privateDisplayAuthenticator struct{}

func (privateDisplayAuthenticator) Challenge(*http.Request) (string, error) { return "", nil }
func (privateDisplayAuthenticator) Authenticate(req *http.Request) (bool, string, string, error) {
	auth.BindPrincipal(req, auth.Principal{Subject: "real-subject", Username: "anonymous", Issuer: "https://idp.test"})
	return true, "anonymous", "", nil
}
func TestPlatformIdentityCookiesAndPrivateCacheMarker(t *testing.T) {
	logging.Logger = zap.NewNop()
	s := &Server{authenticator: privateDisplayAuthenticator{}}
	r := httptest.NewRequest("GET", "http://upstream.test/", nil)
	r.Header.Set("Cookie", "ads_identity_session=credential; ads_oidc_state=state; saml_tracker=state; application=keep")
	_, resp := s.middlewareAuth(r, &goproxy.ProxyCtx{Req: r})
	require.Nil(t, resp)
	require.Equal(t, "application=keep", r.Header.Get("Cookie"))
	r.Header.Del("Cookie")
	r.Header.Del("X-Authenticated-User")
	cfg := cache.DefaultCacheConfig()
	cfg.MemoryEnabled = true
	cfg.MinSizeBytes = 0
	hc := cache.NewHTTPCache(nil, cfg)
	candidate := &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("private")), ContentLength: 7}
	require.False(t, hc.IsCacheable(r, candidate))
	require.False(t, hc.IsCacheable(r.Clone(r.Context()), candidate), "cloning must retain the private marker")
}
func TestPlatformLegacyMTLSDoesNotInventAuthTime(t *testing.T) {
	r := httptest.NewRequest("GET", "https://gateway.test/", nil)
	r.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{{Raw: []byte("cert"), NotAfter: time.Now().Add(time.Hour)}}}}
	bindLegacyPrincipal(r, "anonymous")
	p, ok := auth.PrincipalFromContext(r.Context())
	require.True(t, ok)
	require.Zero(t, p.AuthTime)
}
func TestPlatformAdaptiveRulePriorityAcrossFindings(t *testing.T) {
	e, err := adaptive.New(adaptive.Config{Enabled: true, Mode: "enforce", Rules: []adaptive.Rule{{ID: "sensitive", Category: "sensitive_data", MinConfidence: .8, Action: "block"}, {ID: "fallback", Action: "allow"}}})
	require.NoError(t, err)
	d := e.EvaluateMany([]adaptive.Input{{Tenant: "a", Host: "example.test", Path: "/"}, {Tenant: "a", Host: "example.test", Path: "/", Category: "web", Confidence: 1, FindingExpiresAt: time.Now().Add(time.Minute)}, {Tenant: "a", Host: "example.test", Path: "/", Category: "sensitive_data", Confidence: .9, FindingExpiresAt: time.Now().Add(time.Minute)}})
	require.True(t, d.Blocked)
	require.Equal(t, "sensitive", d.RuleID)
}
