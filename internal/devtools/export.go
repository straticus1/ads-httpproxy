package devtools

import (
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// filterExchanges operates only on the bounded, already-redacted snapshot.
func filterExchanges(entries []Exchange, q url.Values) ([]Exchange, error) {
	status, limit := 0, 0
	var since time.Time
	var err error
	if raw := q.Get("status"); raw != "" {
		status, err = strconv.Atoi(raw)
		if err != nil || status < 0 || status > 599 || (status > 0 && status < 100) {
			return nil, fmt.Errorf("status must be 0 or an HTTP status from 100 to 599")
		}
	}
	if raw := q.Get("limit"); raw != "" {
		limit, err = strconv.Atoi(raw)
		if err != nil || limit < 1 || limit > 10000 {
			return nil, fmt.Errorf("limit must be between 1 and 10000")
		}
	}
	if raw := q.Get("since"); raw != "" {
		since, err = time.Parse(time.RFC3339Nano, raw)
		if err != nil {
			return nil, fmt.Errorf("since must be an RFC3339 timestamp")
		}
	}
	result := make([]Exchange, 0)
	for _, e := range entries {
		u, err := url.Parse(e.URL)
		if q.Get("host") != "" && (err != nil || !strings.EqualFold(u.Host, q.Get("host"))) {
			continue
		}
		if q.Get("method") != "" && e.Method != q.Get("method") {
			continue
		}
		if q.Get("status") != "" && e.Status != status {
			continue
		}
		if !since.IsZero() && e.Started.Before(since) {
			continue
		}
		result = append(result, e)
	}
	// Keep the latest matches, preserving the existing oldest-to-newest order.
	if limit > 0 && len(result) > limit {
		result = result[len(result)-limit:]
	}
	return result, nil
}

type harPair struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

func harHeaders(h http.Header) []harPair {
	result := make([]harPair, 0)
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		for _, v := range h[k] {
			result = append(result, harPair{k, v})
		}
	}
	return result
}

// HAR exports only information already retained by the capture toolkit. Unknown
// sizes and protocol details remain unknown; previews are explicitly annotated.
func HAR(exchanges []Exchange) map[string]any {
	entries := make([]any, 0, len(exchanges))
	for _, e := range exchanges {
		query := make([]harPair, 0)
		if u, err := url.Parse(e.URL); err == nil {
			values := u.Query()
			keys := make([]string, 0, len(values))
			for k := range values {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				for _, v := range values[k] {
					query = append(query, harPair{k, v})
				}
			}
		}
		request := map[string]any{"method": e.Method, "url": e.URL, "httpVersion": "", "cookies": []any{}, "headers": harHeaders(e.RequestHeaders), "queryString": query, "headersSize": -1, "bodySize": -1}
		if e.RequestBody != "" {
			request["postData"] = map[string]any{"mimeType": e.RequestHeaders.Get("Content-Type"), "text": e.RequestBody, "comment": "Captured text preview; may be incomplete."}
		}
		content := map[string]any{"size": -1, "mimeType": e.ResponseHeaders.Get("Content-Type"), "comment": "Body size is unknown; text, when present, is a captured preview."}
		if e.ResponseBody != "" {
			content["text"] = e.ResponseBody
		}
		response := map[string]any{"status": e.Status, "statusText": http.StatusText(e.Status), "httpVersion": e.Protocol, "cookies": []any{}, "headers": harHeaders(e.ResponseHeaders), "content": content, "redirectURL": "", "headersSize": -1, "bodySize": -1}
		entries = append(entries, map[string]any{
			"startedDateTime": e.Started.Format(time.RFC3339Nano), "time": e.DurationMS,
			"request": request, "response": response, "cache": map[string]any{},
			"timings":    map[string]any{"send": 0, "wait": e.DurationMS, "receive": 0, "comment": "Only aggregate duration is measured; wait contains the total, not time to first byte."},
			"_captureID": e.ID, "_requestTruncated": e.RequestTruncated, "_responseTruncated": e.ResponseTruncated, "_error": e.Error, "_mocked": e.Mocked,
		})
	}
	return map[string]any{"log": map[string]any{"version": "1.2", "creator": map[string]string{"name": "ads-httpproxy", "version": "dev"}, "entries": entries, "comment": "Redacted proxy captures. Credential headers and query values are omitted/redacted. Optional body previews may contain secrets. Sizes and request protocol are not measured."}}
}
