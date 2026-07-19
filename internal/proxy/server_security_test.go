package proxy

import (
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"testing"

	"ads-httpproxy/internal/auth"
	"ads-httpproxy/internal/config"
	"ads-httpproxy/pkg/logging"

	"github.com/elazarl/goproxy"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestGatewayHandlerAuthenticatesApplicationRoutes(t *testing.T) {
	logging.Logger = zap.NewNop()
	upstreamCalled := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamCalled = true
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)
	target, err := url.Parse(upstream.URL)
	require.NoError(t, err)

	s := &Server{
		cfg:           &config.Config{Features: &config.FeatureToggles{ReverseProxy: true}},
		authenticator: auth.DenyAllAuthenticator{},
		compiledApps: map[string]*PreparedApp{
			"app.example": {
				Routes: []PreparedAppRoute{{
					Config: config.AppRoute{PathRoute: "/", Upstream: "app"},
					Proxy:  httputil.NewSingleHostReverseProxy(target),
				}},
			},
		},
	}

	req := httptest.NewRequest(http.MethodGet, "http://app.example/private", nil)
	req.Host = "app.example"
	rec := httptest.NewRecorder()
	s.GatewayHandler(rec, req)

	require.Equal(t, http.StatusProxyAuthRequired, rec.Code)
	require.False(t, upstreamCalled)
}

func TestGatewayHandlerRunsSecurityMiddlewareForApplicationRoutes(t *testing.T) {
	logging.Logger = zap.NewNop()
	upstreamCalled := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamCalled = true
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)
	target, err := url.Parse(upstream.URL)
	require.NoError(t, err)
	open, err := auth.NewOpenAuthenticator(nil)
	require.NoError(t, err)
	s := &Server{
		cfg:           &config.Config{Features: &config.FeatureToggles{ReverseProxy: true}},
		authenticator: open,
		middleware: []RequestMiddleware{func(req *http.Request, _ *goproxy.ProxyCtx) (*http.Request, *http.Response) {
			return req, goproxy.NewResponse(req, goproxy.ContentTypeText, http.StatusUnavailableForLegalReasons, "blocked by security middleware")
		}},
		compiledApps: map[string]*PreparedApp{
			"app.example": {Routes: []PreparedAppRoute{{Config: config.AppRoute{PathRoute: "/"}, Proxy: httputil.NewSingleHostReverseProxy(target)}}},
		},
	}
	req := httptest.NewRequest(http.MethodGet, "http://app.example/private", nil)
	req.Host = "app.example"
	rec := httptest.NewRecorder()

	s.GatewayHandler(rec, req)

	require.Equal(t, http.StatusUnavailableForLegalReasons, rec.Code)
	require.False(t, upstreamCalled)
}

func TestGatewayHandlerHonorsDisabledForwardProxy(t *testing.T) {
	logging.Logger = zap.NewNop()
	upstreamCalled := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamCalled = true
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)

	s := &Server{
		cfg:   &config.Config{Features: &config.FeatureToggles{ForwardProxy: false}},
		proxy: goproxy.NewProxyHttpServer(),
	}
	req := httptest.NewRequest(http.MethodGet, upstream.URL, nil)
	rec := httptest.NewRecorder()
	s.GatewayHandler(rec, req)

	require.Equal(t, http.StatusForbidden, rec.Code)
	require.False(t, upstreamCalled)
}

func TestHandleWebSocketRejectsUntrustedUpstreamCertificate(t *testing.T) {
	logging.Logger = zap.NewNop()
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(upstream.Close)
	target, err := url.Parse(upstream.URL)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "http://app.example/socket", nil)
	req.Header.Set("Connection", "upgrade")
	req.Header.Set("Upgrade", "websocket")
	rec := httptest.NewRecorder()

	HandleWebSocket(rec, req, target)

	require.Equal(t, http.StatusBadGateway, rec.Code)
}
