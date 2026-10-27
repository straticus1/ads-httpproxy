package cache

import (
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCachedResponseRetainsUpstreamProtocolForVia(t *testing.T) {
	c := reviewCache()
	req := httptest.NewRequest("GET", "https://origin.test/", nil)
	response := cacheResponse()
	response.Proto, response.ProtoMajor, response.ProtoMinor = "HTTP/2.0", 2, 0
	response.Header.Set("Via", "1.1 origin-edge")
	require.NoError(t, c.Set(req, response))
	defer response.Body.Close()
	hit, ok := c.Get(req)
	require.True(t, ok)
	restored := hit.ToResponse(req)
	defer restored.Body.Close()
	require.Equal(t, "HTTP/2.0", restored.Proto)
	require.Equal(t, 2, restored.ProtoMajor)
	require.Equal(t, 0, restored.ProtoMinor)
	require.Equal(t, "1.1 origin-edge", restored.Header.Get("Via"))
	legacy := (&CachedResponse{StatusCode: 200}).ToResponse(req)
	defer legacy.Body.Close()
	require.Equal(t, "HTTP/1.1", legacy.Proto)
}
