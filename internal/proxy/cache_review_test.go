package proxy

import (
	"ads-httpproxy/internal/cache"
	"ads-httpproxy/internal/config"
	"ads-httpproxy/internal/devtools"
	"ads-httpproxy/internal/dlp"
	"ads-httpproxy/pkg/logging"
	"context"
	"errors"
	"github.com/elazarl/goproxy"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

func TestCachedTrafficStillRunsPoliciesAndIsCaptured(t *testing.T) {
	logging.Logger = zap.NewNop()
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "text/plain")
		io.WriteString(w, strings.Repeat("body", 512))
	}))
	defer upstream.Close()
	cfg := config.NewConfig()
	cfg.Auth.AllowUnauthenticated = true
	cfg.DevTools = &devtools.Config{Enabled: true, CaptureBodies: true}
	s := NewServer(cfg)
	defer s.Shutdown(context.Background())
	cc := cache.DefaultCacheConfig()
	cc.MemoryEnabled = true
	s.httpCache = cache.NewHTTPCache(nil, cc)
	var block atomic.Bool
	s.middleware = append(s.middleware, func(r *http.Request, _ *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		if block.Load() {
			return r, goproxy.NewResponse(r, "text/plain", 403, "policy blocked")
		}
		return r, nil
	})
	var responseChecks atomic.Int32
	s.respMiddleware = append(s.respMiddleware, func(r *http.Response, _ *goproxy.ProxyCtx) *http.Response { responseChecks.Add(1); return r })
	proxy := httptest.NewServer(http.HandlerFunc(s.GatewayHandler))
	defer proxy.Close()
	p, _ := url.Parse(proxy.URL)
	tr := &http.Transport{Proxy: http.ProxyURL(p)}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr}
	for _, want := range []string{"MISS", "HIT"} {
		resp, err := client.Get(upstream.URL)
		require.NoError(t, err)
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		require.NoError(t, err)
		require.Equal(t, strings.Repeat("body", 512), string(body))
		require.Equal(t, want, resp.Header.Get("X-Cache"))
	}
	require.EqualValues(t, 1, calls.Load())
	require.EqualValues(t, 2, responseChecks.Load())
	require.Len(t, s.devtools.List(), 2)
	block.Store(true)
	resp, err := client.Get(upstream.URL)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, 403, resp.StatusCode)
	require.EqualValues(t, 1, calls.Load())
}

type trackedBody struct {
	io.Reader
	closed bool
}

func (b *trackedBody) Close() error { b.closed = true; return nil }

type brokenReader struct{}

func (brokenReader) Read([]byte) (int, error) { return 0, errors.New("broken body") }
func TestDLPHandlesMissingBrokenAndBlockedBodies(t *testing.T) {
	logging.Logger = zap.NewNop()
	scanner, err := dlp.NewVisualDLP([]string{"SECRET"}, "", "", "", 1<<20)
	require.NoError(t, err)
	s := &Server{dlpScanner: scanner}
	req, _ := http.NewRequest("GET", "http://example.test", nil)
	ctx := &goproxy.ProxyCtx{Req: req}
	_, resp := s.middlewareDLP(req, ctx)
	require.Nil(t, resp)
	require.Nil(t, s.middlewareRespDLP(nil, ctx))
	for _, tc := range []struct {
		name                          string
		reader                        func() io.Reader
		requestStatus, responseStatus int
	}{
		{"broken", func() io.Reader { return io.MultiReader(strings.NewReader("prefix"), brokenReader{}) }, 400, 502},
		{"blocked", func() io.Reader { return strings.NewReader("SECRET") }, 403, 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := &trackedBody{Reader: tc.reader()}
			req.Body = b
			_, out := s.middlewareDLP(req, ctx)
			require.NotNil(t, out)
			require.Equal(t, tc.requestStatus, out.StatusCode)
			require.True(t, b.closed)
			b = &trackedBody{Reader: tc.reader()}
			out = s.middlewareRespDLP(&http.Response{StatusCode: 200, Header: make(http.Header), Body: b}, ctx)
			require.Equal(t, tc.responseStatus, out.StatusCode)
			require.True(t, b.closed)
		})
	}
}

type reviewScript struct {
	requests, responses int
	block               bool
}

func (s *reviewScript) Name() string { return "test" }
func (s *reviewScript) Close() error { return nil }
func (s *reviewScript) OnRequest(context.Context, *http.Request) error {
	s.requests++
	if s.block {
		return errors.New("blocked")
	}
	return nil
}
func (s *reviewScript) OnResponse(context.Context, *http.Response) error { s.responses++; return nil }

type reviewTransport func(*http.Request) (*http.Response, error)

func (f reviewTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestCacheHitsRunBothScriptHooks(t *testing.T) {
	logging.Logger = zap.NewNop()
	cc := cache.DefaultCacheConfig()
	cc.MinSizeBytes = 0
	cc.MemoryEnabled = true
	script := &reviewScript{}
	s := &Server{httpCache: cache.NewHTTPCache(nil, cc), scriptEngine: script}
	calls := 0
	tr := s.wrapTransport(reviewTransport(func(req *http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("body")), ContentLength: 4, Request: req}, nil
	}), false)
	for range 2 {
		req, _ := http.NewRequest("GET", "http://example.test", nil)
		resp, err := tr.RoundTrip(req)
		require.NoError(t, err)
		resp.Body.Close()
	}
	require.Equal(t, 1, calls)
	require.Equal(t, 2, script.requests)
	require.Equal(t, 2, script.responses)
	script.block = true
	req, _ := http.NewRequest("GET", "http://example.test", nil)
	_, err := tr.RoundTrip(req)
	require.Error(t, err)
	require.Equal(t, 1, calls)
}
