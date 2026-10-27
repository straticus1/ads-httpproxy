// Package devtools provides opt-in outbound traffic inspection and development rules.
package devtools

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type Config struct {
	Enabled       bool   `json:"enabled" yaml:"enabled"`
	Capacity      int    `json:"capacity" yaml:"capacity"`
	CaptureBodies bool   `json:"capture_bodies" yaml:"capture_bodies"`
	MaxBodyBytes  int    `json:"max_body_bytes" yaml:"max_body_bytes"`
	Rules         []Rule `json:"rules" yaml:"rules"`
}

// Rule matches an exact host and optional path prefix. First matching rule wins.
type Rule struct {
	Host       string      `json:"host" yaml:"host"`
	PathPrefix string      `json:"path_prefix,omitempty" yaml:"path_prefix"`
	Method     string      `json:"method,omitempty" yaml:"method"`
	DelayMS    int         `json:"delay_ms,omitempty" yaml:"delay_ms"`
	Fail       bool        `json:"fail,omitempty" yaml:"fail"`
	Status     int         `json:"status,omitempty" yaml:"status"`
	Body       string      `json:"body,omitempty" yaml:"body"`
	Headers    http.Header `json:"headers,omitempty" yaml:"headers"`
}

type Exchange struct {
	ID                uint64      `json:"id"`
	Started           time.Time   `json:"started"`
	Method            string      `json:"method"`
	URL               string      `json:"url"`
	RequestHeaders    http.Header `json:"request_headers"`
	RequestBody       string      `json:"request_body,omitempty"`
	RequestTruncated  bool        `json:"request_truncated,omitempty"`
	Status            int         `json:"status"`
	Protocol          string      `json:"protocol,omitempty"`
	ResponseHeaders   http.Header `json:"response_headers,omitempty"`
	ResponseBody      string      `json:"response_body,omitempty"`
	ResponseTruncated bool        `json:"response_truncated,omitempty"`
	DurationMS        float64     `json:"duration_ms"`
	Error             string      `json:"error,omitempty"`
	Mocked            bool        `json:"mocked,omitempty"`
}

type Toolkit struct {
	cfg     Config
	mu      sync.RWMutex
	entries []Exchange
	next    uint64
	head    int
	rules   []Rule
}

func Validate(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	if cfg.Capacity < 0 || cfg.Capacity > 10000 {
		return fmt.Errorf("devtools capacity must be between 0 and 10000")
	}
	if cfg.MaxBodyBytes < 0 || cfg.MaxBodyBytes > 65536 {
		return fmt.Errorf("devtools max_body_bytes must be between 0 and 65536")
	}
	return validateRules(cfg.Rules)
}
func validateRules(rules []Rule) error {
	if len(rules) > 100 {
		return fmt.Errorf("at most 100 development rules are allowed")
	}
	for _, r := range rules {
		if r.Host == "" || strings.ContainsAny(r.Host, "/ \r\n") {
			return fmt.Errorf("rule requires an exact host")
		}
		if r.DelayMS < 0 || r.DelayMS > 60000 {
			return fmt.Errorf("rule delay_ms must be between 0 and 60000")
		}
		if r.Status != 0 && (r.Status < 200 || r.Status > 599) {
			return fmt.Errorf("mock status must be between 200 and 599")
		}
		if len(r.Body) > 65536 {
			return fmt.Errorf("mock body exceeds 65536 bytes")
		}
		size := 0
		for key, values := range r.Headers {
			if !validToken(key) {
				return fmt.Errorf("invalid mock header name")
			}
			size += len(key)
			for _, v := range values {
				size += len(v)
				if strings.ContainsAny(v, "\r\n") {
					return fmt.Errorf("invalid mock header value")
				}
			}
		}
		if size > 16384 {
			return fmt.Errorf("mock headers exceed 16384 bytes")
		}
	}
	return nil
}
func validToken(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c > 127 || !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", c)) {
			return false
		}
	}
	return true
}
func New(cfg *Config) *Toolkit {
	if cfg == nil || !cfg.Enabled {
		return nil
	}
	copy := *cfg
	if copy.Capacity == 0 {
		copy.Capacity = 500
	}
	if copy.MaxBodyBytes == 0 {
		copy.MaxBodyBytes = 4096
	}
	t := &Toolkit{cfg: copy}
	_ = t.SetRules(cfg.Rules)
	return t
}
func cloneRules(rules []Rule) []Rule {
	result := append([]Rule(nil), rules...)
	for i := range result {
		result[i].Headers = result[i].Headers.Clone()
	}
	return result
}
func (t *Toolkit) SetRules(rules []Rule) error {
	if err := validateRules(rules); err != nil {
		return err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.rules = cloneRules(rules)
	return nil
}
func (t *Toolkit) Rules() []Rule { t.mu.RLock(); defer t.mu.RUnlock(); return cloneRules(t.rules) }
func (t *Toolkit) add(entry Exchange) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.next++
	entry.ID = t.next
	if len(t.entries) == t.cfg.Capacity {
		t.entries[t.head] = entry
		t.head = (t.head + 1) % t.cfg.Capacity
	} else {
		t.entries = append(t.entries, entry)
	}
}
func (t *Toolkit) List() []Exchange {
	t.mu.RLock()
	defer t.mu.RUnlock()
	result := make([]Exchange, len(t.entries))
	for i := range t.entries {
		e := t.entries[(t.head+i)%len(t.entries)]
		e.RequestHeaders = e.RequestHeaders.Clone()
		e.ResponseHeaders = e.ResponseHeaders.Clone()
		result[i] = e
	}
	return result
}
func (t *Toolkit) Clear() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.entries = nil
	t.head = 0
}
func safeHeaders(h http.Header) http.Header {
	result := http.Header{}
	for _, key := range []string{"Content-Type", "Content-Length", "Accept", "Accept-Encoding", "Cache-Control"} {
		for _, v := range h.Values(key) {
			if len(v) > 1024 {
				v = v[:1024]
			}
			result.Add(key, v)
		}
	}
	return result
}
func safeURL(u *url.URL) string {
	copy := *u
	copy.User = nil
	copy.Fragment = ""
	query := copy.Query()
	for key := range query {
		query.Set(key, "[REDACTED]")
	}
	copy.RawQuery = query.Encode()
	result := copy.String()
	if len(result) > 4096 {
		result = result[:4096]
	}
	return result
}

type preview struct {
	mu        sync.Mutex
	data      []byte
	limit     int
	truncated bool
}

func (p *preview) Write(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := len(b)
	remaining := p.limit - len(p.data)
	if len(b) > remaining {
		p.truncated = true
		b = b[:remaining]
	}
	p.data = append(p.data, b...)
	return n, nil
}
func (p *preview) snapshot() (string, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return strings.ToValidUTF8(string(p.data), "�"), p.truncated
}

type observedBody struct {
	io.ReadCloser
	reader io.Reader
	finish func()
	once   sync.Once
}

func (b *observedBody) Read(p []byte) (int, error) {
	n, err := b.reader.Read(p)
	if err == io.EOF {
		b.once.Do(b.finish)
	}
	return n, err
}
func (b *observedBody) Close() error { err := b.ReadCloser.Close(); b.once.Do(b.finish); return err }
func textBody(h http.Header) bool {
	v := strings.ToLower(h.Get("Content-Type"))
	return strings.HasPrefix(v, "text/") || strings.Contains(v, "json") || strings.Contains(v, "xml") || strings.Contains(v, "x-www-form-urlencoded")
}

type transport struct {
	toolkit *Toolkit
	next    http.RoundTripper
}

func (t *Toolkit) Wrap(next http.RoundTripper) http.RoundTripper {
	if next == nil {
		next = http.DefaultTransport
	}
	if t == nil {
		return next
	}
	return &transport{t, next}
}
func (tr *transport) RoundTrip(req *http.Request) (*http.Response, error) {
	t := tr.toolkit
	start := time.Now()
	entry := Exchange{Started: start, Method: req.Method, URL: safeURL(req.URL), RequestHeaders: safeHeaders(req.Header)}
	requestPreview := &preview{limit: t.cfg.MaxBodyBytes}
	responsePreview := &preview{limit: t.cfg.MaxBodyBytes}
	outgoing := req.Clone(req.Context())
	if t.cfg.CaptureBodies && outgoing.Body != nil && textBody(req.Header) {
		outgoing.Body = &observedBody{ReadCloser: req.Body, reader: io.TeeReader(req.Body, requestPreview), finish: func() {}}
	}
	finish := func() {
		entry.RequestBody, entry.RequestTruncated = requestPreview.snapshot()
		entry.ResponseBody, entry.ResponseTruncated = responsePreview.snapshot()
		entry.DurationMS = float64(time.Since(start).Microseconds()) / 1000
		t.add(entry)
	}
	var resp *http.Response
	var err error
	matched := false
	for _, rule := range t.Rules() {
		if !strings.EqualFold(rule.Host, req.URL.Host) || !strings.HasPrefix(req.URL.Path, rule.PathPrefix) || rule.Method != "" && rule.Method != req.Method {
			continue
		}
		matched = true
		if rule.DelayMS > 0 {
			timer := time.NewTimer(time.Duration(rule.DelayMS) * time.Millisecond)
			select {
			case <-req.Context().Done():
				timer.Stop()
				err = req.Context().Err()
			case <-timer.C:
			}
		}
		if err == nil && rule.Fail {
			err = fmt.Errorf("development failure rule")
		}
		if err == nil && rule.Status != 0 {
			entry.Mocked = true
			headers := rule.Headers.Clone()
			if headers == nil {
				headers = http.Header{}
			}
			if headers.Get("Content-Type") == "" {
				headers.Set("Content-Type", "text/plain; charset=utf-8")
			}
			resp = &http.Response{StatusCode: rule.Status, Status: fmt.Sprintf("%d %s", rule.Status, http.StatusText(rule.Status)), Header: headers, Body: io.NopCloser(strings.NewReader(rule.Body)), ContentLength: int64(len(rule.Body)), Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1, Request: req}
		}
		break
	}
	if resp == nil && err == nil {
		resp, err = tr.next.RoundTrip(outgoing)
	} else if matched && outgoing.Body != nil {
		_ = outgoing.Body.Close()
	}
	if err != nil {
		entry.Error = "upstream request failed"
		if matched {
			entry.Error = err.Error()
		}
		finish()
		return nil, err
	}
	entry.Status = resp.StatusCode
	entry.Protocol = resp.Proto
	entry.ResponseHeaders = safeHeaders(resp.Header)
	// Preserve bidirectional upgrade bodies; no preview wrapping for WebSockets.
	if resp.StatusCode == http.StatusSwitchingProtocols || resp.Body == nil {
		finish()
		return resp, nil
	}
	reader := io.Reader(resp.Body)
	if t.cfg.CaptureBodies && textBody(resp.Header) {
		reader = io.TeeReader(resp.Body, responsePreview)
	}
	resp.Body = &observedBody{ReadCloser: resp.Body, reader: reader, finish: finish}
	return resp, nil
}

// HandleExchanges and HandleRules are mounted behind management API authentication.
func (t *Toolkit) HandleExchanges(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.Method {
	case http.MethodGet:
		format := r.URL.Query().Get("format")
		if format != "" && format != "json" && format != "har" {
			http.Error(w, "format must be json or har", http.StatusBadRequest)
			return
		}
		entries, err := filterExchanges(t.List(), r.URL.Query())
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if format == "har" {
			w.Header().Set("Content-Disposition", `attachment; filename="captures.har"`)
			json.NewEncoder(w).Encode(HAR(entries))
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"exchanges": entries})
	case http.MethodDelete:
		t.Clear()
		json.NewEncoder(w).Encode(map[string]string{"status": "cleared"})
	default:
		w.Header().Set("Allow", "GET, DELETE")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}
func (t *Toolkit) HandleRules(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.Method {
	case http.MethodGet:
		json.NewEncoder(w).Encode(map[string]any{"rules": t.Rules()})
	case http.MethodPut:
		var value struct {
			Rules []Rule `json:"rules"`
		}
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&value); err != nil {
			http.Error(w, "Invalid rules", http.StatusBadRequest)
			return
		}
		if err := decoder.Decode(new(any)); err != io.EOF {
			http.Error(w, "Invalid rules", http.StatusBadRequest)
			return
		}
		if err := t.SetRules(value.Rules); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"status": "updated"})
	default:
		w.Header().Set("Allow", "GET, PUT")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// RequestFromExchange creates a credential-free replay. Query values must be supplied explicitly.
func RequestFromExchange(ctx context.Context, e Exchange, target string) (*http.Request, error) {
	if target == "" {
		if strings.Contains(e.URL, "%5BREDACTED%5D") || strings.Contains(e.URL, "[REDACTED]") {
			return nil, fmt.Errorf("captured query values are redacted; provide -url for replay")
		}
		target = e.URL
	}
	if e.RequestTruncated {
		return nil, fmt.Errorf("captured request body is truncated")
	}
	if e.Method != http.MethodGet && e.Method != http.MethodHead {
		return nil, fmt.Errorf("automatic replay supports GET and HEAD; use request with an explicit method and body")
	}
	req, err := http.NewRequestWithContext(ctx, e.Method, target, bytes.NewBufferString(e.RequestBody))
	if err != nil {
		return nil, err
	}
	req.Header = e.RequestHeaders.Clone()
	return req, nil
}
