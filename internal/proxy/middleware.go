package proxy

import (
	"net"
	"net/http"

	"ads-httpproxy/pkg/logging"

	"github.com/elazarl/goproxy"
	"go.uber.org/zap"
)

// middlewareThreatIntel checks against known malicious IPs and domains.
func (s *Server) middlewareThreatIntel(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	host := req.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}

	// 1. Check IP Blocklist (Local + Feeds)
	if s.threatMgr.IsBlocked(host) {
		logging.Logger.Warn("Blocked request to malicious IP", zap.String("host", host))
		return req, goproxy.NewResponse(req, goproxy.ContentTypeText, http.StatusForbidden, "Access Denied: Threat Detected (IP)")
	}

	// 2. Check DNS Science Cache (Enhanced scoring)
	blocked, score, err := s.threatMgr.CheckDomainViaCache(req.Context(), host)
	if err != nil {
		// Fail open on error to avoid outage
		logging.Logger.Debug("Threat lookup failed", zap.Error(err))
	} else if blocked {
		logging.Logger.Warn("Blocked request to malicious domain",
			zap.String("domain", host),
			zap.Int("score", score))
		return req, goproxy.NewResponse(req, goproxy.ContentTypeText, http.StatusForbidden, "Access Denied: Threat Detected (Domain)")
	}

	return req, nil
}

// middlewareGeoIP checks if the client IP originates from a blocked country.
func (s *Server) middlewareGeoIP(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	clientIP, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		clientIP = req.RemoteAddr
	}

	// Check Allow/Block rules
	if !s.geoIP.IsAllowed(clientIP, s.cfg.GeoIPAllow, s.cfg.GeoIPBlock) {
		logging.Logger.Warn("Blocked request from disallowed country", zap.String("ip", clientIP))
		return req, goproxy.NewResponse(req, goproxy.ContentTypeText, http.StatusForbidden, "Access Denied: GeoIP Location Blocked")
	}

	return req, nil
}

// middlewareAuth enforces authentication policies.
func (s *Server) middlewareAuth(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	// Skip auth for internal health checks if needed, but handled by apiServer usually.

	authenticated, user, challenge, err := s.authenticator.Authenticate(req)
	if err != nil {
		logging.Logger.Error("Authentication error", zap.Error(err))
		return req, goproxy.NewResponse(req, goproxy.ContentTypeText, http.StatusInternalServerError, "Internal Server Error during Auth")
	}

	if !authenticated {
		// If challenge is present, return it to prompt user
		if challenge != "" {
			resp := goproxy.NewResponse(req, goproxy.ContentTypeText, http.StatusProxyAuthRequired, "Proxy Authentication Required")
			resp.Header.Set("Proxy-Authenticate", challenge)
			return req, resp
		}
		// Otherwise just reject
		return req, goproxy.NewResponse(req, goproxy.ContentTypeText, http.StatusProxyAuthRequired, "Proxy Authentication Required")
	}

	// Use Zap logger context to track user for this request?
	// goproxy doesn't propagate context easily to recursive handlers, but we can set headers
	logging.Logger.Debug("Authenticated request", zap.String("user", user))
	req.Header.Set("X-Authenticated-User", user)

	return req, nil
}

// middlewareWAF detects malicious payloads in URL and Headers.
func (s *Server) middlewareWAF(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	// Scan URL
	if blocked, reason := s.wafScanner.Scan(req.URL.String()); blocked {
		logging.Logger.Warn("WAF Blocked URL", zap.String("reason", reason), zap.String("url", req.URL.String()))
		return req, goproxy.NewResponse(req, goproxy.ContentTypeText, http.StatusForbidden, "Access Denied: WAF Block (URL)")
	}

	// Scan Headers (User-Agent, Referer, etc)
	// For performance, maybe just specific ones or dump.
	for k, v := range req.Header {
		for _, val := range v {
			if blocked, reason := s.wafScanner.Scan(val); blocked {
				logging.Logger.Warn("WAF Blocked Header", zap.String("header", k), zap.String("reason", reason))
				return req, goproxy.NewResponse(req, goproxy.ContentTypeText, http.StatusForbidden, "Access Denied: WAF Block (Header)")
			}
		}
	}

	return req, nil
}
