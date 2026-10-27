package auth

import (
	"ads-httpproxy/internal/config"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	"go.uber.org/zap"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"
)

type SAMLAuthenticator struct {
	replayMu   sync.Mutex
	assertions map[string]time.Time
	cfg        *config.SAMLConfig
	logger     *zap.Logger
	sp         *samlsp.Middleware
	root       *url.URL
	sessions   *browserSessions
}

func NewSAMLAuthenticator(cfg *config.SAMLConfig, logger *zap.Logger) (*SAMLAuthenticator, error) {
	if err := config.ValidateIdentity(&config.AuthConfig{Mechanism: "saml", SAML: cfg}); err != nil {
		return nil, err
	}
	pair, err := loadKeyPair(cfg.Cert, cfg.Key)
	if err != nil {
		return nil, err
	}
	signer, ok := pair.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, errors.New("SAML key must be an RSA or P-256 signing key")
	}
	switch key := signer.(type) {
	case *rsa.PrivateKey:
		if key.N.BitLen() < 2048 {
			return nil, errors.New("SAML RSA key must be at least 2048 bits")
		}
	case *ecdsa.PrivateKey:
		if key.Curve != elliptic.P256() {
			return nil, errors.New("SAML EC key must use P-256")
		}
	default:
		return nil, errors.New("unsupported SAML signing key")
	}
	root, _ := url.Parse(cfg.RootURL)
	client := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", cfg.MetadataURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, errors.New("SAML metadata request failed")
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
	if err != nil || len(data) > 1<<20 {
		return nil, errors.New("SAML metadata exceeds limit")
	}
	metadata, err := samlsp.ParseMetadata(data)
	if err != nil {
		return nil, err
	}
	for _, descriptor := range metadata.IDPSSODescriptors {
		for _, service := range descriptor.SingleSignOnServices {
			if _, err := config.IdentityURL(service.Location); err != nil {
				return nil, err
			}
		}
	}
	sameSite := http.SameSiteNoneMode
	if root.Scheme != "https" {
		sameSite = http.SameSiteLaxMode
	}
	sp, err := samlsp.New(samlsp.Options{URL: *root, Key: signer, Certificate: pair.Leaf, IDPMetadata: metadata, HTTPClient: client, CookieSameSite: sameSite, AllowIDPInitiated: false, DefaultRedirectURI: "/"})
	if err != nil {
		return nil, err
	}
	copy := *cfg
	a := &SAMLAuthenticator{assertions: make(map[string]time.Time), cfg: &copy, logger: logger, sp: sp, root: root, sessions: newBrowserSessions(root, 10000, time.Hour)}
	sp.Session = &samlSessionProvider{auth: a}
	sp.OnError = func(w http.ResponseWriter, _ *http.Request, _ error) {
		http.Error(w, "SAML authentication failed", http.StatusUnauthorized)
	}
	return a, nil
}
func loadKeyPair(certPath, keyPath string) (tls.Certificate, error) {
	pair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return tls.Certificate{}, err
	}
	if pair.Leaf == nil {
		pair.Leaf, err = x509.ParseCertificate(pair.Certificate[0])
		if err != nil {
			return tls.Certificate{}, err
		}
	}
	if time.Now().Before(pair.Leaf.NotBefore) || !time.Now().Before(pair.Leaf.NotAfter) {
		return tls.Certificate{}, errors.New("SAML certificate is not currently valid")
	}
	return pair, nil
}
func (a *SAMLAuthenticator) Challenge(*http.Request) (string, error) { return "SAML", nil }
func (a *SAMLAuthenticator) Authenticate(req *http.Request) (bool, string, string, error) {
	p, ok := a.sessions.get(req)
	if !ok {
		return false, "", "", nil
	}
	BindPrincipal(req, p)
	return true, p.Username, "", nil
}
func (a *SAMLAuthenticator) Handler() http.Handler { return a.sp }
func (a *SAMLAuthenticator) HandleBrowser(w http.ResponseWriter, r *http.Request) bool {
	if !browserHost(r, a.root) {
		return false
	}
	if r.URL.Path != "/auth/login" && r.URL.Path != "/auth/logout" && r.URL.Path != a.sp.ServiceProvider.MetadataURL.Path && r.URL.Path != a.sp.ServiceProvider.AcsURL.Path {
		return false
	}
	w.Header().Set("Cache-Control", "no-store")
	switch r.URL.Path {
	case "/auth/login":
		if r.Method != "GET" {
			w.Header().Set("Allow", "GET")
			http.Error(w, "Method not allowed", 405)
			return true
		}
		copy := r.Clone(r.Context())
		copy.URL, _ = url.Parse(localReturnPath(r.URL.Query().Get("return")))
		a.sp.HandleStartAuthFlow(w, copy)
	case "/auth/logout":
		a.sessions.logout(w, r)
	case a.sp.ServiceProvider.MetadataURL.Path:
		if r.Method != "GET" {
			w.Header().Set("Allow", "GET")
			http.Error(w, "Method not allowed", 405)
		} else {
			a.sp.ServeHTTP(w, r)
		}
	case a.sp.ServiceProvider.AcsURL.Path:
		if r.Method != "POST" {
			w.Header().Set("Allow", "POST")
			http.Error(w, "Method not allowed", 405)
		} else {
			r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
			a.sp.ServeHTTP(w, r)
		}
	default:
		return false
	}
	return true
}
func (a *SAMLAuthenticator) RevokeSubject(subject string) int {
	return a.sessions.RevokeSubject(subject)
}

type samlSessionProvider struct{ auth *SAMLAuthenticator }

func (p *samlSessionProvider) CreateSession(w http.ResponseWriter, r *http.Request, assertion *saml.Assertion) error {
	if assertion == nil {
		return errors.New("missing assertion")
	}
	attrs := make(samlsp.Attributes)
	for _, statement := range assertion.AttributeStatements {
		for _, attr := range statement.Attributes {
			for _, value := range attr.Values {
				attrs[attr.Name] = append(attrs[attr.Name], value.Value)
				if attr.FriendlyName != "" && attr.FriendlyName != attr.Name {
					attrs[attr.FriendlyName] = append(attrs[attr.FriendlyName], value.Value)
				}
			}
		}
	}
	principal := Principal{Issuer: p.auth.sp.ServiceProvider.IDPMetadata.EntityID, ExpiresAt: time.Now().Add(time.Hour)}
	if assertion.Subject != nil && assertion.Subject.NameID != nil {
		principal.Subject = assertion.Subject.NameID.Value
	}
	if p.auth.cfg.SubjectAttribute != "" {
		principal.Subject = attrs.Get(p.auth.cfg.SubjectAttribute)
	}
	if principal.Subject == "" {
		return errors.New("SAML assertion has no stable subject")
	}
	principal.Username = attrs.Get("uid")
	if principal.Username == "" {
		principal.Username = attrs.Get("urn:oid:0.9.2342.19200300.100.1.1")
	}
	if principal.Username == "" {
		principal.Username = principal.Subject
	}
	groups := p.auth.cfg.GroupsAttribute
	if groups == "" {
		groups = "groups"
	}
	principal.Groups = append([]string(nil), attrs[groups]...)
	tenant := p.auth.cfg.TenantAttribute
	if tenant == "" {
		tenant = "tenant"
	}
	principal.Tenant = attrs.Get(tenant)
	principal.DeviceID = attrs.Get("device_id")
	if assertion.Conditions != nil && !assertion.Conditions.NotOnOrAfter.IsZero() && assertion.Conditions.NotOnOrAfter.Before(principal.ExpiresAt) {
		principal.ExpiresAt = assertion.Conditions.NotOnOrAfter
	}
	for _, statement := range assertion.AuthnStatements {
		principal.AuthTime = statement.AuthnInstant
		if statement.SessionNotOnOrAfter != nil && statement.SessionNotOnOrAfter.Before(principal.ExpiresAt) {
			principal.ExpiresAt = *statement.SessionNotOnOrAfter
		}
		if statement.AuthnContext.AuthnContextClassRef != nil {
			principal.ACR = statement.AuthnContext.AuthnContextClassRef.Value
		}
	}
	if assertion.ID == "" {
		return errors.New("SAML assertion has no ID")
	}
	p.auth.replayMu.Lock()
	now := time.Now()
	for id, expiry := range p.auth.assertions {
		if !now.Before(expiry) {
			delete(p.auth.assertions, id)
		}
	}
	if _, exists := p.auth.assertions[assertion.ID]; exists {
		p.auth.replayMu.Unlock()
		return errors.New("SAML assertion replay")
	}
	if len(p.auth.assertions) >= 10000 {
		p.auth.replayMu.Unlock()
		return errors.New("SAML replay cache capacity reached")
	}
	p.auth.assertions[assertion.ID] = principal.ExpiresAt
	p.auth.replayMu.Unlock()
	return p.auth.sessions.create(w, r, principal)
}
func (p *samlSessionProvider) DeleteSession(w http.ResponseWriter, r *http.Request) error {
	p.auth.sessions.delete(w, r)
	return nil
}
func (p *samlSessionProvider) GetSession(r *http.Request) (samlsp.Session, error) {
	principal, ok := p.auth.sessions.get(r)
	if !ok {
		return nil, samlsp.ErrNoSession
	}
	return principal, nil
}
