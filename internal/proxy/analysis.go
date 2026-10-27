package proxy

import (
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"ads-httpproxy/internal/adaptive"
	"ads-httpproxy/internal/analysis"
	"ads-httpproxy/internal/auth"
	"github.com/elazarl/goproxy"
)

func requestTenant(req *http.Request) string {
	p, ok := auth.PrincipalFromContext(req.Context())
	if ok && p.Tenant != "" {
		return p.Tenant
	}
	return "default"
}
func eventFor(req *http.Request, status int, decision, reason string) analysis.Event {
	p, _ := auth.PrincipalFromContext(req.Context())
	u := *req.URL
	if u.Host == "" {
		u.Host = req.Host
		if req.TLS != nil {
			u.Scheme = "https"
		} else {
			u.Scheme = "http"
		}
	}
	return analysis.Event{Tenant: requestTenant(req), Subject: p.Subject, Method: req.Method, URL: u.String(), Status: status, Timestamp: time.Now().UTC(), RequestHeaders: req.Header, Decision: decision, Reason: reason}
}
func (s *Server) recordDecision(req *http.Request, status int, reason string) {
	if s.analysis != nil {
		event := eventFor(req, status, "block", reason)
		s.analysis.Submit(event)
	}
}
func (s *Server) adaptiveDecision(req *http.Request) adaptive.Decision {
	in := adaptive.Input{Tenant: requestTenant(req), Host: req.URL.Host, Path: req.URL.EscapedPath()}
	if in.Host == "" {
		in.Host = req.Host
	}
	// Host/path rules work immediately. Classification rules consume only fresh,
	// tenant-isolated findings; asynchronous results cannot block a past request.
	inputs := []adaptive.Input{in}
	if s.analysis != nil && s.adaptive != nil {
		for _, f := range s.analysis.Snapshot(analysis.Filter{Tenant: in.Tenant, Limit: 1000}) {
			u, err := url.Parse(f.URL)
			if err != nil || !strings.EqualFold(u.Host, in.Host) || u.EscapedPath() != in.Path {
				continue
			}
			candidate := in
			candidate.Category = f.Category
			candidate.Confidence = f.Confidence
			candidate.FindingExpiresAt = f.ExpiresAt
			inputs = append(inputs, candidate)
		}
	}
	return s.adaptive.EvaluateMany(inputs)
}

type enforcementTransport struct {
	s    *Server
	next http.RoundTripper
}

func (t *enforcementTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := t.s.aiGate.Check(req, requestTenant(req)); err != nil {
		if req.Body != nil {
			req.Body.Close()
		}
		return goproxy.NewResponse(req, "text/plain", 403, err.Error()), nil
	}
	d := t.s.adaptiveDecision(req)
	if d.Blocked {
		if req.Body != nil {
			req.Body.Close()
		}
		return goproxy.NewResponse(req, "text/plain", 403, d.Reason), nil
	}
	resp, err := t.next.RoundTrip(req)
	if resp != nil && d.WouldBlock {
		if resp.Header == nil {
			resp.Header = make(http.Header)
		}
		resp.Header.Set("X-ADS-Adaptive", "shadow-block")
	}
	return resp, err
}

type sampleBuffer struct {
	mu    sync.Mutex
	bytes []byte
	max   int
}

func (b *sampleBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := len(p)
	left := b.max - len(b.bytes)
	if len(p) > left {
		p = p[:left]
	}
	b.bytes = append(b.bytes, p...)
	return n, nil
}
func (b *sampleBuffer) String() string { b.mu.Lock(); defer b.mu.Unlock(); return string(b.bytes) }

type sampledBody struct {
	io.ReadCloser
	reader io.Reader
	once   sync.Once
	finish func()
}

func (b *sampledBody) Read(p []byte) (int, error) {
	n, err := b.reader.Read(p)
	if err != nil {
		b.once.Do(b.finish)
	}
	return n, err
}
func (b *sampledBody) Close() error { err := b.ReadCloser.Close(); b.once.Do(b.finish); return err }

type observationTransport struct {
	s    *Server
	next http.RoundTripper
}

func (t *observationTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.s.analysis == nil {
		return t.next.RoundTrip(req)
	}
	e := eventFor(req, 0, "allow", "")
	e.RequestHeaders = req.Header.Clone()
	limit := 0
	if t.s.cfg.Analysis.CaptureBodies {
		limit = t.s.cfg.Analysis.MaxBodyBytes
		if limit == 0 {
			limit = 4096
		}
	}
	requestPreview := &sampleBuffer{max: limit}
	responsePreview := &sampleBuffer{max: limit}
	if req.Body != nil && limit > 0 {
		req.Body = &sampledBody{ReadCloser: req.Body, reader: io.TeeReader(req.Body, requestPreview), finish: func() {}}
	}
	resp, err := t.next.RoundTrip(req)
	if err != nil {
		e.Decision = "error"
		e.Reason = "upstream request failed"
		t.s.analysis.Submit(e)
		return resp, err
	}
	e.Status = resp.StatusCode
	e.ResponseHeaders = resp.Header.Clone()
	if resp.StatusCode == 403 || resp.StatusCode == 429 {
		e.Decision = "block"
		e.Reason = "request enforcement rejected traffic"
	}
	if t.s.adaptive != nil {
		e.PolicyVersion = strconv.FormatUint(t.s.adaptive.Snapshot().Version, 10)
	}
	finish := func() {
		e.RequestBody = requestPreview.String()
		e.ResponseBody = responsePreview.String()
		t.s.analysis.Submit(e)
	}
	if resp.Body == nil || resp.StatusCode == http.StatusSwitchingProtocols {
		finish()
		return resp, nil
	}
	resp.Body = &sampledBody{ReadCloser: resp.Body, reader: io.TeeReader(resp.Body, responsePreview), finish: finish}
	return resp, nil
}
