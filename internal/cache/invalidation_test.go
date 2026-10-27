package cache

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/stretchr/testify/require"
)

func storeValue(t *testing.T, hc *HTTPCache, req *http.Request, value string) {
	t.Helper()
	resp := &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(value)), ContentLength: int64(len(value))}
	require.NoError(t, hc.Set(req, resp))
}

func TestPurgeInvalidatesAllURLVariants(t *testing.T) {
	hc := reviewCache()
	var requests []*http.Request
	for _, method := range []string{"GET", "HEAD"} {
		for _, host := range []string{"example.test", "virtual.test"} {
			for _, encoding := range []string{"", "gzip", "br"} {
				req := httptest.NewRequest(method, "https://example.test/resource?a=1", nil)
				req.Host = host
				req.Header.Set("Accept-Encoding", encoding)
				storeValue(t, hc, req, "before")
				requests = append(requests, req)
			}
		}
	}
	for _, req := range requests {
		_, ok := hc.Get(req)
		require.True(t, ok)
	}
	require.NoError(t, hc.Purge("https://example.test/resource?a=1"))
	for _, req := range requests {
		_, ok := hc.Get(req)
		require.False(t, ok, "%s %s %s", req.Method, req.Host, req.Header.Get("Accept-Encoding"))
	}
	for _, target := range []string{"/relative", "file:///tmp/data", "https://user:secret@example.test/"} {
		require.Error(t, hc.Purge(target))
	}
}

func TestInflightFillCannotResurrectPurgedResponse(t *testing.T) {
	for _, all := range []bool{false, true} {
		hc := reviewCache()
		req := httptest.NewRequest("GET", "https://example.test/resource", nil)
		generation := hc.Begin(req)
		if all {
			require.NoError(t, hc.PurgeAll())
		} else {
			require.NoError(t, hc.Purge(req.URL.String()))
		}
		resp := cacheResponse()
		require.NoError(t, hc.SetIfCurrent(req, resp, generation))
		_, ok := hc.Get(req)
		require.False(t, ok)
		storeValue(t, hc, req, "fresh")
		cached, ok := hc.Get(req)
		require.True(t, ok)
		require.Equal(t, "fresh", string(cached.Body))
	}
}

func TestSuccessfulMutationsInvalidateOnlySameOriginRelatedURLs(t *testing.T) {
	for _, method := range []string{"POST", "PUT", "PATCH", "DELETE", "CUSTOM"} {
		t.Run(method, func(t *testing.T) {
			hc := reviewCache()
			targets := []string{"https://example.test/item", "https://example.test/related", "https://example.test/content", "https://other.test/unrelated"}
			for _, target := range targets {
				storeValue(t, hc, httptest.NewRequest("GET", target, nil), "old")
			}
			req := httptest.NewRequest(method, targets[0], nil)
			resp := &http.Response{StatusCode: 201, Header: http.Header{"Location": {targets[3], "/related"}, "Content-Location": {"https://example.test:443/content"}}}
			require.NoError(t, hc.Invalidate(req, resp))
			for i, target := range targets {
				_, ok := hc.Get(httptest.NewRequest("GET", target, nil))
				require.Equal(t, i == 3, ok, target)
			}
		})
	}
}

func TestFailedWritesAndSafeMethodsDoNotInvalidate(t *testing.T) {
	hc := reviewCache()
	req := httptest.NewRequest("GET", "http://example.test/resource", nil)
	storeValue(t, hc, req, "old")
	for _, method := range []string{"GET", "HEAD", "OPTIONS", "TRACE"} {
		r := req.Clone(req.Context())
		r.Method = method
		require.NoError(t, hc.Invalidate(r, &http.Response{StatusCode: 200}))
		_, ok := hc.Get(req)
		require.True(t, ok)
	}
	for _, status := range []int{400, 403, 500} {
		r := req.Clone(req.Context())
		r.Method = "POST"
		require.NoError(t, hc.Invalidate(r, &http.Response{StatusCode: status}))
		_, ok := hc.Get(req)
		require.True(t, ok)
	}
}

// Optional real Redis integration, with an isolated Unix socket and no TCP
// listener. CI can install redis-server to exercise cross-instance semantics.
func TestRedisGenerationsInvalidateOtherInstanceMemory(t *testing.T) {
	binary, err := exec.LookPath("redis-server")
	if err != nil {
		t.Skip("redis-server not installed")
	}
	directory, err := os.MkdirTemp("/tmp", "ads-cache-redis-")
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(directory) })
	socket := filepath.Join(directory, "redis.sock")
	cmd := exec.Command(binary, "--port", "0", "--unixsocket", socket, "--save", "", "--appendonly", "no")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	client := redis.NewClient(&redis.Options{Network: "unix", Addr: socket})
	t.Cleanup(func() { client.Close() })
	require.Eventually(t, func() bool { return client.Ping(context.Background()).Err() == nil }, 3*time.Second, 10*time.Millisecond)
	newCache := func() *HTTPCache {
		cfg := DefaultCacheConfig()
		cfg.MinSizeBytes = 0
		return NewHTTPCache(&Manager{client: client}, cfg)
	}
	a, b := newCache(), newCache()
	req := httptest.NewRequest("GET", "https://example.test/resource", nil)
	storeValue(t, a, req, "old")
	_, ok := b.Get(req)
	require.True(t, ok) // populate B's L1
	stale := b.Begin(req)
	require.NoError(t, a.Purge(req.URL.String()))
	_, ok = b.Get(req)
	require.False(t, ok)
	require.NoError(t, b.SetIfCurrent(req, cacheResponse(), stale))
	_, ok = a.Get(req)
	require.False(t, ok)
	storeValue(t, b, req, "new")
	entry, ok := a.Get(req)
	require.True(t, ok)
	require.Equal(t, "new", string(entry.Body))
	require.NoError(t, a.PurgeAll())
	_, ok = b.Get(req)
	require.False(t, ok)
	// Losing generation keys (e.g. Redis restart/eviction) must never expose old L1.
	storeValue(t, a, req, "before-reset")
	require.NoError(t, client.FlushDB(context.Background()).Err())
	_, ok = a.Get(req)
	require.False(t, ok)
	// A failed invalidation must not leave a local L1 hit usable.
	storeValue(t, a, req, "last")
	require.NoError(t, client.Close())
	require.Error(t, a.Purge(req.URL.String()))
	_, ok = a.Get(req)
	require.False(t, ok)
}
