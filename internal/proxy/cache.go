package proxy

import (
	"net/http"

	"ads-httpproxy/internal/cache"
	"ads-httpproxy/pkg/logging"
	"go.uber.org/zap"
)

// Cache only at the outbound transport boundary. Every hit must still pass
// request policies, scripts and plugins, and the response inspection pipeline.
type cacheTransport struct {
	next  http.RoundTripper
	cache *cache.HTTPCache
}

func (t *cacheTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if cached, ok := t.cache.Get(req); ok {
		if req.Body != nil {
			req.Body.Close()
		}
		return cached.ToResponse(req), nil
	}
	generation := t.cache.Begin(req)
	resp, err := t.next.RoundTrip(req)
	if err != nil {
		return resp, err
	}
	// Set consumes and restores a bounded prefix before returning ownership of
	// the body to the caller. Never read a live response in a background goroutine.
	if err := t.cache.Invalidate(req, resp); err != nil {
		logging.Logger.Warn("Failed to invalidate cache after mutation; cache disabled", zap.Error(err))
	}
	if err := t.cache.SetIfCurrent(req, resp, generation); err != nil {
		logging.Logger.Warn("Failed to cache response", zap.Error(err))
	}
	if resp.Header == nil {
		resp.Header = make(http.Header)
	}
	resp.Header.Set("X-Cache", "MISS")
	return resp, nil
}
