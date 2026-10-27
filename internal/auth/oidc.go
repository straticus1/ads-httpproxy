package auth

import (
	"ads-httpproxy/internal/config"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"github.com/coreos/go-oidc/v3/oidc"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type loginAttempt struct {
	Nonce, Verifier, ReturnPath string
	Expires                     time.Time
}
type OIDCAuthenticator struct {
	cfg      *config.OIDCConfig
	logger   *zap.Logger
	provider *oidc.Provider
	verifier *oidc.IDTokenVerifier
	client   *http.Client
	oauth    oauth2.Config
	root     *url.URL
	sessions *browserSessions
	mu       sync.Mutex
	pending  map[string]loginAttempt
}

func NewOIDCAuthenticator(cfg *config.OIDCConfig, logger *zap.Logger) (*OIDCAuthenticator, error) {
	if err := config.ValidateIdentity(&config.AuthConfig{Mechanism: "oidc", OIDC: cfg}); err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	ctx, cancel := context.WithTimeout(oidc.ClientContext(context.Background(), client), 10*time.Second)
	defer cancel()
	provider, err := oidc.NewProvider(ctx, cfg.Issuer)
	if err != nil {
		return nil, err
	}
	var metadata struct {
		JWKSURL string `json:"jwks_uri"`
	}
	if err := provider.Claims(&metadata); err != nil {
		return nil, errors.New("invalid OIDC provider metadata")
	}
	if _, err := config.IdentityURL(metadata.JWKSURL); err != nil {
		return nil, err
	}
	// Use a live client context for JWKS refresh, not the discovery timeout context.
	verifier := provider.VerifierContext(oidc.ClientContext(context.Background(), client), &oidc.Config{ClientID: cfg.ClientID})
	copy := *cfg
	copy.Scopes = append([]string(nil), cfg.Scopes...)
	a := &OIDCAuthenticator{cfg: &copy, logger: logger, provider: provider, verifier: verifier, client: client, pending: make(map[string]loginAttempt)}
	if cfg.RedirectURL != "" {
		a.root, _ = url.Parse(cfg.RedirectURL)
		ttl := time.Hour
		if cfg.SessionTTLSeconds > 0 {
			ttl = time.Duration(cfg.SessionTTLSeconds) * time.Second
		}
		capacity := 10000
		if cfg.SessionCapacity > 0 {
			capacity = cfg.SessionCapacity
		}
		a.sessions = newBrowserSessions(a.root, capacity, ttl)
		scopes := []string{oidc.ScopeOpenID}
		for _, scope := range cfg.Scopes {
			if scope != oidc.ScopeOpenID {
				scopes = append(scopes, scope)
			}
		}
		endpoint := provider.Endpoint()
		if _, err := config.IdentityURL(endpoint.AuthURL); err != nil {
			return nil, err
		}
		if _, err := config.IdentityURL(endpoint.TokenURL); err != nil {
			return nil, err
		}
		a.oauth = oauth2.Config{ClientID: cfg.ClientID, ClientSecret: cfg.ClientSecret, RedirectURL: cfg.RedirectURL, Endpoint: endpoint, Scopes: scopes}
	}
	return a, nil
}
func (a *OIDCAuthenticator) Challenge(*http.Request) (string, error) {
	return `Bearer realm="ads-proxy", scope="openid"`, nil
}
func (a *OIDCAuthenticator) Authenticate(req *http.Request) (bool, string, string, error) {
	if a.sessions != nil {
		if p, ok := a.sessions.get(req); ok {
			BindPrincipal(req, p)
			return true, p.Username, "", nil
		}
	}
	if !a.cfg.AllowLegacyIDTokens {
		return false, "", "", nil
	}
	token := bearerToken(req)
	if token == "" {
		return false, "", "", nil
	}
	idToken, err := a.verifier.Verify(oidc.ClientContext(req.Context(), a.client), token)
	if err != nil {
		return false, "", "", nil
	}
	p, err := a.principal(idToken)
	if err != nil {
		return false, "", "", err
	}
	BindPrincipal(req, p)
	return true, p.Username, "", nil
}
func (a *OIDCAuthenticator) principal(token *oidc.IDToken) (Principal, error) {
	var claims map[string]json.RawMessage
	if err := token.Claims(&claims); err != nil {
		return Principal{}, errors.New("invalid identity claims")
	}
	p := Principal{Subject: token.Subject, Username: token.Subject, Issuer: token.Issuer, ExpiresAt: token.Expiry}
	if p.Subject == "" {
		return p, errors.New("identity has no subject")
	}
	// Stable issuer+subject remains the security identity; preferred_username is display only.
	var username string
	_ = json.Unmarshal(claims["preferred_username"], &username)
	if username != "" {
		p.Username = username
	}
	groups := a.cfg.GroupsClaim
	if groups == "" {
		groups = "groups"
	}
	if raw := claims[groups]; len(raw) > 0 {
		if err := json.Unmarshal(raw, &p.Groups); err != nil {
			return p, errors.New("groups claim must be a string array")
		}
	}
	tenant := a.cfg.TenantClaim
	if tenant == "" {
		tenant = "tenant"
	}
	if raw := claims[tenant]; len(raw) > 0 {
		if err := json.Unmarshal(raw, &p.Tenant); err != nil {
			return p, errors.New("tenant claim must be a string")
		}
	}
	_ = json.Unmarshal(claims["device_id"], &p.DeviceID)
	_ = json.Unmarshal(claims["amr"], &p.AMR)
	_ = json.Unmarshal(claims["acr"], &p.ACR)
	var authTime int64
	_ = json.Unmarshal(claims["auth_time"], &authTime)
	if authTime > 0 {
		p.AuthTime = time.Unix(authTime, 0)
	}
	return p, nil
}
func (a *OIDCAuthenticator) HandleBrowser(w http.ResponseWriter, r *http.Request) bool {
	if !browserHost(r, a.root) {
		return false
	}
	switch r.URL.Path {
	case "/auth/login":
		if r.Method != "GET" {
			w.Header().Set("Allow", "GET")
			http.Error(w, "Method not allowed", 405)
		} else {
			a.login(w, r)
		}
	case "/auth/logout":
		a.sessions.logout(w, r)
	default:
		if r.URL.Path != a.root.Path {
			return false
		}
		if r.Method != "GET" {
			w.Header().Set("Allow", "GET")
			http.Error(w, "Method not allowed", 405)
		} else {
			a.callback(w, r)
		}
	}
	return true
}
func (a *OIDCAuthenticator) login(w http.ResponseWriter, r *http.Request) {
	state, err := randomSecret()
	if err != nil {
		http.Error(w, "Login unavailable", 503)
		return
	}
	nonce, err := randomSecret()
	if err != nil {
		http.Error(w, "Login unavailable", 503)
		return
	}
	a.mu.Lock()
	now := time.Now()
	for key, attempt := range a.pending {
		if !now.Before(attempt.Expires) {
			delete(a.pending, key)
		}
	}
	if len(a.pending) >= a.sessions.capacity {
		a.mu.Unlock()
		http.Error(w, "Login capacity reached", 503)
		return
	}
	attempt := loginAttempt{Nonce: nonce, Verifier: oauth2.GenerateVerifier(), ReturnPath: localReturnPath(r.URL.Query().Get("return")), Expires: now.Add(5 * time.Minute)}
	a.pending[state] = attempt
	a.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "ads_oidc_state", Value: state, Path: a.root.Path, Secure: a.root.Scheme == "https", HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: 300})
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, a.oauth.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(attempt.Verifier)), http.StatusFound)
}
func (a *OIDCAuthenticator) callback(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	state := r.URL.Query().Get("state")
	cookie, err := r.Cookie("ads_oidc_state")
	if err != nil || state == "" || len(state) > 128 || subtle.ConstantTimeCompare([]byte(state), []byte(cookie.Value)) != 1 {
		http.Error(w, "Invalid login state", 400)
		return
	}
	a.mu.Lock()
	attempt, ok := a.pending[state]
	delete(a.pending, state)
	a.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "ads_oidc_state", Path: a.root.Path, Secure: a.root.Scheme == "https", HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: -1})
	if !ok || !time.Now().Before(attempt.Expires) || r.URL.Query().Get("code") == "" || r.URL.Query().Get("error") != "" {
		http.Error(w, "Invalid or expired login", 400)
		return
	}
	ctx, cancel := context.WithTimeout(oidc.ClientContext(r.Context(), a.client), 10*time.Second)
	defer cancel()
	token, err := a.oauth.Exchange(ctx, r.URL.Query().Get("code"), oauth2.VerifierOption(attempt.Verifier))
	if err != nil {
		http.Error(w, "Token exchange failed", 401)
		return
	}
	raw, ok := token.Extra("id_token").(string)
	if !ok || len(raw) > 64<<10 {
		http.Error(w, "Missing identity token", 401)
		return
	}
	idToken, err := a.verifier.Verify(ctx, raw)
	if err != nil || subtle.ConstantTimeCompare([]byte(idTokenNonce(idToken)), []byte(attempt.Nonce)) != 1 {
		http.Error(w, "Invalid identity token", 401)
		return
	}
	if idToken.AccessTokenHash != "" && idToken.VerifyAccessToken(token.AccessToken) != nil {
		http.Error(w, "Invalid access token binding", 401)
		return
	}
	p, err := a.principal(idToken)
	if err != nil {
		http.Error(w, "Invalid identity", 401)
		return
	}
	if scope, ok := token.Extra("scope").(string); ok {
		p.Scopes = strings.Fields(scope)
	}
	if err := a.sessions.create(w, r, p); err != nil {
		http.Error(w, "Session unavailable", 503)
		return
	}
	http.Redirect(w, r, attempt.ReturnPath, http.StatusSeeOther)
}
func idTokenNonce(token *oidc.IDToken) string {
	if token == nil {
		return ""
	}
	return token.Nonce
}
func (a *OIDCAuthenticator) RevokeSubject(subject string) int {
	if a.sessions == nil {
		return 0
	}
	return a.sessions.RevokeSubject(subject)
}
