package cache

import (
	"ads-httpproxy/pkg/logging"
	"encoding/json"
	"errors"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func reviewCache() *HTTPCache {
	logging.Logger = zap.NewNop()
	cfg := DefaultCacheConfig()
	cfg.MemoryEnabled = true
	cfg.MinSizeBytes = 0
	return NewHTTPCache(nil, cfg)
}
func cacheResponse() *http.Response {
	return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("public body"))}
}
func TestSharedCacheBypassesSensitiveAndConditionalRequests(t *testing.T) {
	hc := reviewCache()
	req := httptest.NewRequest("GET", "http://example.test/", nil)
	require.NoError(t, hc.Set(req, cacheResponse()))
	_, ok := hc.Get(req)
	require.True(t, ok)
	for _, header := range []string{"Authorization", "Proxy-Authorization", "Cookie", "Range", "If-None-Match", "If-Modified-Since", "If-Match", "If-Unmodified-Since", "Cache-Control", "X-Authenticated-User"} {
		t.Run(header, func(t *testing.T) {
			r := req.Clone(req.Context())
			r.Header.Set(header, "no-cache")
			_, ok := hc.Get(r)
			require.False(t, ok)
			require.False(t, hc.IsCacheable(r, cacheResponse()))
		})
	}
}
func TestSharedCacheRejectsUnsupportedResponses(t *testing.T) {
	hc := reviewCache()
	req := httptest.NewRequest("GET", "http://example.test/", nil)
	for _, tc := range []struct{ header, value string }{
		{"Cache-Control", "no-cache"}, {"Cache-Control", "private"}, {"Cache-Control", "No-Store"},
		{"Cache-Control", "max-age=0"}, {"Cache-Control", "s-maxage=0, max-age=3600"},
		{"Cache-Control", "max-age=invalid"}, {"Expires", time.Now().Add(-time.Hour).Format(http.TimeFormat)},
		{"Vary", "Cookie"}, {"Vary", "Accept-Encoding, Accept-Language"}, {"Set-Cookie", "session=secret"},
	} {
		t.Run(tc.value, func(t *testing.T) {
			r := cacheResponse()
			r.Header.Set(tc.header, tc.value)
			require.False(t, hc.IsCacheable(req, r))
		})
	}
	r := cacheResponse()
	r.StatusCode = 206
	require.False(t, hc.IsCacheable(req, r))
	r = cacheResponse()
	r.Header.Add("Cache-Control", "public")
	r.Header.Add("Cache-Control", "no-store")
	require.False(t, hc.IsCacheable(req, r))
}
func TestCacheKeyPreservesOriginSemantics(t *testing.T) {
	hc := reviewCache()
	for _, pair := range [][2]string{{"http://example.test/a%2Fb", "http://example.test/a/b"}, {"http://example.test/?a=1&b=2", "http://example.test/?b=2&a=1"}, {"http://example.test/", "http://example.test/?"}} {
		require.NotEqual(t, hc.GenerateKey(httptest.NewRequest("GET", pair[0], nil)), hc.GenerateKey(httptest.NewRequest("GET", pair[1], nil)))
	}
	a := httptest.NewRequest("GET", "/path", nil)
	b := a.Clone(a.Context())
	a.Host = "one.test"
	b.Host = "two.test"
	require.NotEqual(t, hc.GenerateKey(a), hc.GenerateKey(b))
	b = a.Clone(a.Context())
	b.Header.Set("X-Authenticated-User", "alice")
	require.False(t, hc.IsCacheable(b, cacheResponse()))
}
func TestExpiredPayloadCannotOutliveItsFreshness(t *testing.T) {
	hc := reviewCache()
	req := httptest.NewRequest("GET", "http://example.test/", nil)
	data, err := json.Marshal(&CachedResponse{CachedAt: time.Now().Add(-time.Hour), TTL: time.Second})
	require.NoError(t, err)
	hc.memory.Set(hc.generationKey(req, hc.Begin(req)), data, time.Hour)
	_, ok := hc.Get(req)
	require.False(t, ok)
	resp := cacheResponse()
	resp.Header.Set("Cache-Control", "max-age=60")
	resp.Header.Set("Age", "61")
	require.LessOrEqual(t, hc.CalculateTTL(resp), time.Duration(0))
}
func TestCacheReadErrorPreservesBytesAndError(t *testing.T) {
	hc := reviewCache()
	req := httptest.NewRequest("GET", "http://example.test/", nil)
	failure := errors.New("upstream truncated")
	resp := cacheResponse()
	resp.Body = io.NopCloser(io.MultiReader(strings.NewReader("prefix"), failedReader{failure}))
	require.ErrorIs(t, hc.Set(req, resp), failure)
	body, err := io.ReadAll(resp.Body)
	require.Equal(t, "prefix", string(body))
	require.ErrorIs(t, err, failure)
	_, ok := hc.Get(req)
	require.False(t, ok)
}

func TestMemoryCacheRejectsObjectsLargerThanBudget(t *testing.T) {
	mc := NewMemoryCache(1, time.Minute)
	mc.Set("small", []byte("keep"), time.Minute)
	mc.Set("large", make([]byte, (1<<20)+1), time.Minute)
	_, ok := mc.Get("large")
	require.False(t, ok)
	data, ok := mc.Get("small")
	require.True(t, ok)
	require.Equal(t, "keep", string(data))
}
func TestCachePreservesRepeatedHeaders(t *testing.T) {
	hc := reviewCache()
	req := httptest.NewRequest("GET", "http://example.test/", nil)
	resp := cacheResponse()
	resp.Header.Add("Link", "</one>; rel=preload")
	resp.Header.Add("Link", "</two>; rel=preload")
	require.NoError(t, hc.Set(req, resp))
	cached, ok := hc.Get(req)
	require.True(t, ok)
	require.Equal(t, resp.Header.Values("Link"), cached.ToResponse(req).Header.Values("Link"))
}

func TestStreamingResponsesAreNotBuffered(t *testing.T) {
	hc := reviewCache()
	req := httptest.NewRequest("GET", "http://example.test/", nil)
	for _, tc := range []struct {
		length      int64
		contentType string
	}{{-1, "text/plain"}, {1 << 30, "text/plain"}, {0, "text/event-stream"}} {
		resp := cacheResponse()
		resp.ContentLength = tc.length
		resp.Header.Set("Content-Type", tc.contentType)
		resp.Body = io.NopCloser(failedReader{errors.New("must not read streaming body")})
		require.NoError(t, hc.Set(req, resp))
		_, ok := hc.Get(req)
		require.False(t, ok)
	}
}
