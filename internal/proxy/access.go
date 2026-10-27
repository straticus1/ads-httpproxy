package proxy

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"

	"ads-httpproxy/internal/access"
	"ads-httpproxy/internal/auth"
	"ads-httpproxy/internal/policy"
	"github.com/elazarl/goproxy"
	"golang.org/x/time/rate"
)

func clientIdentity(r *http.Request) access.Identity {
	p, _ := auth.PrincipalFromContext(r.Context())
	id := access.Identity{Subject: p.Subject, Issuer: p.Issuer, DeviceID: p.DeviceID, Groups: p.Groups, Scopes: p.Scopes, AMR: p.AMR, AuthTime: p.AuthTime}
	if r.TLS != nil && len(r.TLS.VerifiedChains) > 0 && len(r.TLS.VerifiedChains[0]) > 0 {
		cert := r.TLS.VerifiedChains[0][0]
		id.VerifiedMTLS = true
		if id.DeviceID == "" {
			id.DeviceID = fmt.Sprintf("sha256:%x", sha256.Sum256(cert.Raw))
		}
	}
	return id
}
func (s *Server) middlewareAccess(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	if err := s.access.Check(req.Context(), clientIdentity(req)); err != nil {
		return req, goproxy.NewResponse(req, "text/plain", http.StatusForbidden, "Access denied: "+err.Error())
	}
	return req, nil
}

func (s *Server) gatewayTLSConfig() (*tls.Config, error) {
	if s.cfg.GatewayTLS == nil {
		return nil, nil
	}
	c := s.cfg.GatewayTLS
	cert, err := tls.LoadX509KeyPair(c.Cert, c.Key)
	if err != nil {
		return nil, err
	}
	result := &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}}
	if c.ClientCA != "" {
		data, err := os.ReadFile(c.ClientCA)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(data) {
			return nil, fmt.Errorf("gateway client CA contains no certificates")
		}
		result.ClientCAs = pool
		result.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return result, nil
}

// Policy request limits are per compiled action and instance, independent of byte limits.
type actionLimits struct {
	mu      sync.Mutex
	entries map[string]*rate.Limiter
}

func (a *actionLimits) allow(action string, n int) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.entries == nil {
		a.entries = make(map[string]*rate.Limiter)
	}
	l := a.entries[action]
	if l == nil {
		if len(a.entries) >= 1000 {
			return false
		}
		l = rate.NewLimiter(rate.Limit(n), n)
		a.entries[action] = l
	}
	return l.Allow()
}
func (s *Server) applyPolicyActions(req *http.Request, actions []string, scope string) (int, error) {
	requestOps, responseOps, err := policy.HeaderActions(actions)
	if err != nil {
		return 500, err
	}
	addHeaderActions(req, requestOps, responseOps)
	for _, action := range actions {
		name, arg, _ := strings.Cut(action, ":")
		switch name {
		case "redact_headers":
			for _, h := range strings.Split(arg, ",") {
				req.Header.Del(strings.TrimSpace(h))
			}
		case "set_header", "append_header", "remove_header", "response_set_header", "response_append_header", "response_remove_header":
			if name == "remove_header" {
				req.Header.Del(arg)
			}
		case "rate_limit":
			n, err := strconv.Atoi(arg)
			if err != nil || n < 1 || n > 100000 {
				return 500, fmt.Errorf("invalid policy rate limit")
			}
			if !s.actionLimits.allow(scope+":"+action, n) {
				return 429, fmt.Errorf("policy request limit exceeded")
			}
		default:
			return 500, fmt.Errorf("unsupported policy action")
		}
	}
	return 0, nil
}

func bindLegacyPrincipal(req *http.Request, user string) {
	if _, ok := auth.PrincipalFromContext(req.Context()); ok {
		return
	}
	p := auth.Principal{Subject: user, Username: user, Issuer: "local"}
	if req.TLS != nil && len(req.TLS.VerifiedChains) > 0 && len(req.TLS.VerifiedChains[0]) > 0 {
		c := req.TLS.VerifiedChains[0][0]
		if user == "" || user == "anonymous" {
			p.Subject = fmt.Sprintf("certificate:%x", sha256.Sum256(c.Raw))
			p.Username = c.Subject.CommonName
			p.Issuer = c.Issuer.String()
			p.ExpiresAt = c.NotAfter

			p.AMR = []string{"mtls"}
		}
	}
	auth.BindPrincipal(req, p)
}

// Gateway-owned credentials must not be exposed to protected applications.
func stripIdentityCookies(req *http.Request) {
	cookies := req.Cookies()
	req.Header.Del("Cookie")
	for _, c := range cookies {
		if c.Name == "ads_identity_session" || c.Name == "ads_oidc_state" || strings.HasPrefix(c.Name, "saml_") {
			continue
		}
		req.AddCookie(c)
	}
}
