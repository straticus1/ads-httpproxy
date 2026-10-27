package devtools

import (
	"encoding/json"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestCaptureFilteringAndHARExport(t *testing.T) {
	toolkit := New(&Config{Enabled: true})
	now := time.Now().UTC()
	for _, e := range []Exchange{
		{Started: now.Add(-time.Hour), URL: "https://other.test/", Method: "GET", Status: 200},
		{Started: now, URL: "https://example.test/a?token=%5BREDACTED%5D", Method: "POST", Status: 201, Protocol: "HTTP/2.0", DurationMS: 5, RequestBody: "preview", ResponseBody: "partial", ResponseTruncated: true, RequestHeaders: http.Header{"Content-Type": {"text/plain"}}},
		{Started: now, URL: "https://example.test/b", Method: "GET", Status: 500},
	} {
		toolkit.add(e)
	}
	q := url.Values{"host": {"EXAMPLE.test"}, "method": {"POST"}, "status": {"201"}, "since": {now.Add(-time.Minute).Format(time.RFC3339Nano)}, "limit": {"1"}, "format": {"har"}}
	w := httptest.NewRecorder()
	toolkit.HandleExchanges(w, httptest.NewRequest("GET", "/api/devtools/exchanges?"+q.Encode(), nil))
	require.Equal(t, 200, w.Code)
	require.Contains(t, w.Header().Get("Content-Disposition"), "captures.har")
	var result struct {
		Log struct {
			Version string
			Entries []struct {
				Request struct {
					URL         string
					QueryString []harPair
				}
				Response  struct{ Content struct{ Text string } }
				Truncated bool `json:"_responseTruncated"`
			}
		}
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))
	require.Equal(t, "1.2", result.Log.Version)
	require.Len(t, result.Log.Entries, 1)
	e := result.Log.Entries[0]
	require.Equal(t, "[REDACTED]", e.Request.QueryString[0].Value)
	require.Equal(t, "partial", e.Response.Content.Text)
	require.True(t, e.Truncated)
	w = httptest.NewRecorder()
	toolkit.HandleExchanges(w, httptest.NewRequest("GET", "/api/devtools/exchanges?limit=1", nil))
	var listed struct{ Exchanges []Exchange }
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &listed))
	require.Len(t, listed.Exchanges, 1)
	require.Equal(t, 500, listed.Exchanges[0].Status)
}
func TestCaptureFiltersRejectInvalidInput(t *testing.T) {
	toolkit := New(&Config{Enabled: true})
	for _, q := range []string{"format=xml", "status=wat", "status=99", "status=600", "limit=0", "limit=-1", "limit=10001", "since=yesterday"} {
		w := httptest.NewRecorder()
		toolkit.HandleExchanges(w, httptest.NewRequest("GET", "/api/devtools/exchanges?"+q, nil))
		require.Equal(t, 400, w.Code, q)
	}
	w := httptest.NewRecorder()
	toolkit.HandleExchanges(w, httptest.NewRequest("GET", "/api/devtools/exchanges?format=har", nil))
	require.Equal(t, 200, w.Code)
	require.Contains(t, w.Body.String(), `"entries":[]`)
}
func TestHARPreservesCaptureRedaction(t *testing.T) {
	toolkit := New(&Config{Enabled: true, Rules: []Rule{{Host: "example.test", Status: 200, Body: "ok"}}})
	req := httptest.NewRequest("GET", "https://user:password@example.test/?token=secret", nil)
	req.Header.Set("Authorization", "Bearer secret")
	req.Header.Set("Cookie", "session=secret")
	resp, err := toolkit.Wrap(nil).RoundTrip(req)
	require.NoError(t, err)
	resp.Body.Close()
	data, err := json.Marshal(HAR(toolkit.List()))
	require.NoError(t, err)
	require.NotContains(t, string(data), "password")
	require.NotContains(t, string(data), "Bearer secret")
	require.NotContains(t, string(data), "session=secret")
	require.False(t, strings.Contains(string(data), "token=secret"))
}
