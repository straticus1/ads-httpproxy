package proxy

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"ads-httpproxy/internal/config"
	"ads-httpproxy/internal/headerpolicy"
	"github.com/elazarl/goproxy"
	"github.com/stretchr/testify/require"
)

func headerConnectParent(t *testing.T) (*url.URL, <-chan http.Header) {
	t.Helper()
	received := make(chan http.Header, 1)
	parent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received <- r.Header.Clone()
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
		_ = rw.Flush()
	}))
	t.Cleanup(parent.Close)
	u, err := url.Parse(parent.URL)
	require.NoError(t, err)
	return u, received
}

func TestParentCONNECTHeaderDefaults(t *testing.T) {
	parent, received := headerConnectParent(t)
	conn, err := dialParentCONNECT(context.Background(), parent, "tcp", "example.test:443")
	require.NoError(t, err)
	defer conn.Close()
	headers := <-received
	require.Equal(t, "1.1 ads-proxy", headers.Get("Via"))
	require.Empty(t, headers.Get("User-Agent"))
}

func TestParentCONNECTConfiguredHeadersAndImmutableIngress(t *testing.T) {
	parent, received := headerConnectParent(t)
	parent.User = url.UserPassword("operator", "parent-secret")
	policy, err := headerpolicy.New(&headerpolicy.Config{
		ViaPseudonym:   "edge",
		TrustedProxies: []string{"192.0.2.0/24"},
		Forward:        headerpolicy.Profile{Forwarded: "both", Request: headerpolicy.Operations{Set: map[string][]string{"X-Configured": {"yes"}}}},
	})
	require.NoError(t, err)
	cfg := config.NewConfig()
	cfg.ParentProxy = parent.String()
	s := &Server{cfg: cfg, headerPolicy: policy, proxy: goproxy.NewProxyHttpServer()}
	s.trackConnectDialer()
	req := httptest.NewRequest(http.MethodConnect, "http://example.test:443", nil)
	req.RemoteAddr = "192.0.2.10:1234"
	req.Header = http.Header{"Via": {"1.0 previous"}, "X-Forwarded-For": {"198.51.100.20"}, "Authorization": {"Bearer origin"}, "Cookie": {"session=secret"}, "Proxy-Authorization": {"Basic caller"}, "X-Authenticated-User": {"forged"}}
	s.prepareHeaders(req, false)
	// A later mutation must not replace the captured trusted chain.
	req.Header.Set("X-Forwarded-For", "forged")
	addHeaderActions(req, headerpolicy.Operations{Set: map[string][]string{"X-Policy": {"applied"}}}, headerpolicy.Operations{})
	conn, err := s.proxy.ConnectDialWithReq(req, "tcp", "example.test:443")
	require.NoError(t, err)
	defer conn.Close()
	headers := <-received
	require.Equal(t, []string{"1.0 previous", "1.1 edge"}, headers.Values("Via"))
	require.Contains(t, headers.Get("X-Forwarded-For"), "198.51.100.20")
	require.NotContains(t, headers.Get("X-Forwarded-For"), "forged")
	require.Equal(t, "yes", headers.Get("X-Configured"))
	require.Equal(t, "applied", headers.Get("X-Policy"))
	require.Empty(t, headers.Get("User-Agent"))
	require.Empty(t, headers.Get("Authorization"))
	require.Empty(t, headers.Get("Cookie"))
	require.Empty(t, headers.Get("X-Authenticated-User"))
	require.Equal(t, "Basic "+base64.StdEncoding.EncodeToString([]byte("operator:parent-secret")), headers.Get("Proxy-Authorization"))
	require.Equal(t, "Bearer origin", req.Header.Get("Authorization"), "handshake must not mutate caller headers")
}
