package cache

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"ads-httpproxy/pkg/logging"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

type errorAfterReader struct {
	remaining int
}

func (r *errorAfterReader) Read(p []byte) (int, error) {
	if r.remaining == 0 {
		return 0, errors.New("cache read exceeded configured limit")
	}
	if len(p) > r.remaining {
		p = p[:r.remaining]
	}
	for i := range p {
		p[i] = 'x'
	}
	r.remaining -= len(p)
	return len(p), nil
}

func TestSetStopsBufferingAfterMaximumCacheSize(t *testing.T) {
	logging.Logger = zap.NewNop()
	cfg := DefaultCacheConfig()
	cfg.MemoryEnabled = false
	cfg.MinSizeBytes = 0
	cfg.MaxSizeBytes = 8
	hc := NewHTTPCache(nil, cfg)
	req, _ := http.NewRequest(http.MethodGet, "http://example.test/data", nil)
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       io.NopCloser(&errorAfterReader{remaining: 9}),
	}

	require.NoError(t, hc.Set(req, resp))
}

func TestSetPreservesOversizedResponseForDownstream(t *testing.T) {
	logging.Logger = zap.NewNop()
	cfg := DefaultCacheConfig()
	cfg.MemoryEnabled = false
	cfg.MinSizeBytes = 0
	cfg.MaxSizeBytes = 8
	hc := NewHTTPCache(nil, cfg)
	req, _ := http.NewRequest(http.MethodGet, "http://example.test/data", nil)
	resp := &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("0123456789abcdef"))}

	require.NoError(t, hc.Set(req, resp))
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, "0123456789abcdef", string(body))
}
