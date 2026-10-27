package proxy

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"

	"github.com/quic-go/quic-go/http3"
)

// upstreamTransport selects HTTP/3 only for explicitly configured HTTPS authorities.
// It never retries a failed HTTP/3 request over TCP (which could duplicate a write).
type upstreamTransport struct {
	next  http.RoundTripper
	h3    *http3.Transport
	hosts []string
}

func (t *upstreamTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme == "https" {
		for _, host := range t.hosts {
			if strings.EqualFold(host, req.URL.Host) {
				return t.h3.RoundTrip(req)
			}
		}
	}
	return t.next.RoundTrip(req)
}
func (s *Server) quicTLSConfig() (*tls.Config, error) {
	if s.cfg.QUICCert != "" || s.cfg.QUICKey != "" {
		cert, err := tls.LoadX509KeyPair(s.cfg.QUICCert, s.cfg.QUICKey)
		if err != nil {
			return nil, fmt.Errorf("QUIC certificate: %w", err)
		}
		return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}}, nil
	}
	if s.certManager != nil {
		return s.certManager.TLSConfig(), nil
	}
	return nil, fmt.Errorf("enable_quic requires quic_cert and quic_key, or autocert_cache_dir with configured domains")
}
func (s *Server) wrapTransport(next http.RoundTripper, chain bool) http.RoundTripper {
	if next == nil {
		if s.proxy != nil {
			next = s.proxy.Tr
		} else {
			next = http.DefaultTransport
		}
	}
	if s.h3Transport != nil && !chain {
		next = &upstreamTransport{next: next, h3: s.h3Transport, hosts: s.cfg.QUICUpstreams}
	}
	if s.httpCache != nil {
		next = &cacheTransport{next: next, cache: s.httpCache}
	}
	next = s.devtools.Wrap(next)
	if s.aiGate != nil || s.adaptive != nil {
		next = &enforcementTransport{s: s, next: next}
	}
	if s.scriptEngine != nil {
		next = &scriptTransport{next: next, engine: s.scriptEngine}
	}
	if s.analysis != nil {
		next = &observationTransport{s: s, next: next}
	}
	return next
}
