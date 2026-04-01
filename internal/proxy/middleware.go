package proxy

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync" // Added sync for Pool

	"ads-httpproxy/internal/policy"
	"ads-httpproxy/internal/visibility" // Import visibility
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
		visibility.RecordWAFViolation("url", reason)
		return req, goproxy.NewResponse(req, goproxy.ContentTypeText, http.StatusForbidden, "Access Denied: WAF Block (URL)")
	}

	// Scan Headers (User-Agent, Referer, etc)
	// For performance, maybe just specific ones or dump.
	for k, v := range req.Header {
		for _, val := range v {
			if blocked, reason := s.wafScanner.Scan(val); blocked {
				logging.Logger.Warn("WAF Blocked Header", zap.String("header", k), zap.String("reason", reason))
				visibility.RecordWAFViolation("header", reason)
				return req, goproxy.NewResponse(req, goproxy.ContentTypeText, http.StatusForbidden, "Access Denied: WAF Block (Header)")
			}
		}
	}

	return req, nil
}

// middlewarePolicy evaluates CEL policies.
func (s *Server) middlewarePolicy(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	// Extract Context
	user := req.Header.Get("X-Authenticated-User")
	evalCtx := policy.NewEvalContext(req, user, "") // TODO: Group support

	// Check Policies
	if s.policyEngine == nil {
		return req, nil
	}
	allowed, matched, actions, reason := s.policyEngine.Evaluate(req.Context(), evalCtx)
	if !allowed {
		logging.Logger.Warn("Blocked by Policy",
			zap.String("reason", reason),
			zap.Strings("actions", actions))
		return req, goproxy.NewResponse(req, goproxy.ContentTypeText, http.StatusForbidden, "Access Denied: "+reason)
	}

	if matched {
		logging.Logger.Debug("Policy Matched", zap.String("reason", reason))
	}

	return req, nil
}

// middlewareReputation checks URL against the external Reputation Service and local feeds.
func (s *Server) middlewareReputation(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	urlStr := req.URL.String()

	// Check local URL reputation feeds first (faster, no network)
	if s.feedManager != nil {
		if entry, found := s.feedManager.Check(urlStr); found {
			logging.Logger.Warn("Blocked by URL Reputation Feed",
				zap.String("url", urlStr),
				zap.String("category", entry.Category),
				zap.Int("threat_score", entry.ThreatScore),
				zap.Strings("sources", entry.Sources),
				zap.Strings("tags", entry.Tags))

			msg := fmt.Sprintf("Access Denied: Malicious URL Detected (%s - Score: %d) - Sources: %v",
				entry.Category, entry.ThreatScore, entry.Sources)
			visibility.RecordReputationBlock(entry.Category)
			return req, goproxy.NewResponse(req, goproxy.ContentTypeText, http.StatusForbidden, msg)
		}
	}

	// Check external reputation service (if configured)
	if s.reputation == nil {
		return req, nil
	}

	result, err := s.reputation.Check(req.Context(), urlStr)
	if err != nil {
		// Client handles fail-open logic and logs errors.
		return req, nil
	}

	if result.Blocked {
		logging.Logger.Warn("Blocked by Reputation Service",
			zap.String("url", urlStr),
			zap.String("risk_level", result.RiskLevel),
			zap.Float64("score", result.Score),
			zap.Strings("categories", result.Categories))

		msg := fmt.Sprintf("Access Denied: High Risk URL (%s - Score: %.0f)", result.RiskLevel, result.Score)
		visibility.RecordReputationBlock(result.RiskLevel)
		return req, goproxy.NewResponse(req, goproxy.ContentTypeText, http.StatusForbidden, msg)
	}

	if len(result.Categories) > 0 {
		logging.Logger.Debug("Reputation Categories",
			zap.String("url", urlStr),
			zap.Strings("cats", result.Categories))
	}

	return req, nil
}

// middlewarePeering handles parent selection via CARP/ICP/HTCP.
func (s *Server) middlewarePeering(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	if s.peerMgr == nil {
		return req, nil
	}
	parent := s.peerMgr.SelectParent(req)
	if parent != "" {
		logging.Logger.Debug("Peering: Selected Parent", zap.String("parent", parent))
		// In a real implementation, we would set the proxy upstream here.
		// For now, we log the selection.
	}
	return req, nil
}

// bufferPool reuse buffers to avoid allocs
var bufferPool = sync.Pool{
	New: func() interface{} {
		// Use a fixed size buffer for max scan size
		return make([]byte, 1024*1024)
	},
}

// ParametricReadCloser helper
type ParametricReadCloser struct {
	io.Reader
	Closer func() error
}

func (p *ParametricReadCloser) Close() error {
	if p.Closer != nil {
		return p.Closer()
	}
	return nil
}

// middlewareDLP checks request body for sensitive data.
func (s *Server) middlewareDLP(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	if s.dlpScanner == nil {
		return req, nil
	}

	buf := bufferPool.Get().([]byte)
	const maxScanSize = 1024 * 1024 // 1MB
	scanBuf := buf[:maxScanSize]

	// Read up to limit
	n, err := io.ReadFull(io.LimitReader(req.Body, int64(maxScanSize)), scanBuf)
	// io.ReadFull returns EOF or ErrUnexpectedEOF if shorter than limit, which is fine
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		bufferPool.Put(buf)
		logging.Logger.Error("Failed to read request body for DLP", zap.Error(err))
		return req, nil
	}

	data := scanBuf[:n]

	// Run VisualDLP Scan
	res := s.dlpScanner.ScanRequest(req.URL.String(), data)
	if res.Blocked {
		bufferPool.Put(buf)
		logging.Logger.Warn("DLP Blocked Request",
			zap.String("url", req.URL.String()),
			zap.String("reason", res.Reason),
			zap.Any("evidence", res.Evidence))
		visibility.RecordDLPViolation("request", res.Reason)
		return req, goproxy.NewResponse(req, goproxy.ContentTypeText, http.StatusForbidden, "Access Denied: "+res.Reason)
	}

	orphanedBody := req.Body
	rc := &ParametricReadCloser{
		Reader: io.MultiReader(bytes.NewReader(data), orphanedBody),
		Closer: func() error {
			defer bufferPool.Put(buf)
			return orphanedBody.Close()
		},
	}
	req.Body = rc

	return req, nil
}

// middlewareICAP sends request to ICAP server for modification.
func (s *Server) middlewareICAP(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	if s.icapClient == nil {
		return req, nil
	}
	modifiedReq, err := s.icapClient.ReqMod(req)
	if err != nil {
		logging.Logger.Error("ICAP ReqMod failed", zap.Error(err))
		return req, nil
	}
	return modifiedReq, nil
}

// middlewareRespDLP checks response body for sensitive data.
func (s *Server) middlewareRespDLP(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
	if s.dlpScanner == nil {
		return resp
	}

	buf := bufferPool.Get().([]byte)
	const maxScanSize = 1024 * 1024
	scanBuf := buf[:maxScanSize]

	n, err := io.ReadFull(io.LimitReader(resp.Body, int64(maxScanSize)), scanBuf)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		bufferPool.Put(buf)
		logging.Logger.Error("Failed to read response body for DLP", zap.Error(err))
		return resp
	}
	data := scanBuf[:n]

	// Use ScanUpload for response (generic content scan)
	res := s.dlpScanner.ScanUpload(ctx.Req.URL.String(), data)
	if res.Blocked {
		bufferPool.Put(buf)
		logging.Logger.Warn("DLP Blocked Response",
			zap.String("url", ctx.Req.URL.String()),
			zap.String("reason", res.Reason))
		visibility.RecordDLPViolation("response", res.Reason)
		return goproxy.NewResponse(ctx.Req, goproxy.ContentTypeText, http.StatusForbidden, "Access Denied: "+res.Reason)
	}

	orphanedBody := resp.Body
	rc := &ParametricReadCloser{
		Reader: io.MultiReader(bytes.NewReader(data), orphanedBody),
		Closer: func() error {
			defer bufferPool.Put(buf)
			return orphanedBody.Close()
		},
	}
	resp.Body = rc

	return resp
}

// middlewareRespICAP sends response to ICAP server.
func (s *Server) middlewareRespICAP(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
	modifiedResp, err := s.icapClient.RespMod(resp)
	if err != nil {
		logging.Logger.Error("ICAP RespMod failed", zap.Error(err))
		return resp
	}
	return modifiedResp
}
