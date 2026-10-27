package analysis

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

var credentialPattern = regexp.MustCompile(`(?i)("?(?:password|passwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|authorization)"?\s*[:=]\s*"?)[^"\s,&}]+`)
var bearerPattern = regexp.MustCompile(`(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+`)

func bounded(s string, n int) string {
	if len(s) > n {
		s = s[:n]
	}
	return strings.ToValidUTF8(s, "")
}

func safeURL(value string) string {
	u, err := url.Parse(bounded(value, 4096))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return ""
	}
	u.User, u.Fragment = nil, ""
	q := u.Query()
	for key := range q {
		q.Set(key, "[REDACTED]")
	}
	u.RawQuery = q.Encode()
	return bounded(u.String(), 4096)
}

func safeHeaders(h http.Header) http.Header {
	result := make(http.Header)
	for _, key := range []string{"Content-Type", "Content-Length"} {
		if value := h.Get(key); value != "" {
			result.Set(key, bounded(value, 256))
		}
	}
	return result
}

func preview(value string, max int) string {
	value = bounded(value, max)
	value = credentialPattern.ReplaceAllString(value, "${1}[REDACTED]")
	value = bearerPattern.ReplaceAllString(value, "Bearer [REDACTED]")
	return bounded(value, max)
}

func textContent(h http.Header) bool {
	ct := strings.ToLower(h.Get("Content-Type"))
	return strings.HasPrefix(ct, "text/") || strings.Contains(ct, "json") || strings.Contains(ct, "xml") || strings.Contains(ct, "x-www-form-urlencoded")
}

func sanitize(e Event, cfg Config) Event {
	e.ID, e.Tenant, e.Subject = bounded(e.ID, 128), bounded(e.Tenant, 128), bounded(e.Subject, 256)
	if e.Tenant == "" {
		e.Tenant = "default"
	}
	e.URL, e.Method, e.PolicyVersion = safeURL(e.URL), bounded(e.Method, 32), bounded(e.PolicyVersion, 128)
	switch e.Decision {
	case "allow", "block", "error", "":
	default:
		e.Decision = "error"
	}
	e.Reason = preview(e.Reason, 1024)
	e.RequestHeaders, e.ResponseHeaders = safeHeaders(e.RequestHeaders), safeHeaders(e.ResponseHeaders)
	if !cfg.CaptureBodies || !textContent(e.RequestHeaders) {
		e.RequestBody = ""
	} else {
		e.RequestBody = preview(e.RequestBody, cfg.MaxBodyBytes)
	}
	if !cfg.CaptureBodies || !textContent(e.ResponseHeaders) {
		e.ResponseBody = ""
	} else {
		e.ResponseBody = preview(e.ResponseBody, cfg.MaxBodyBytes)
	}
	return e
}

func sensitiveKey(key string) bool {
	key = strings.ToLower(key)
	for _, name := range []string{"password", "passwd", "secret", "token", "authorization", "cookie", "api_key", "apikey"} {
		if strings.Contains(key, name) {
			return true
		}
	}
	return false
}
