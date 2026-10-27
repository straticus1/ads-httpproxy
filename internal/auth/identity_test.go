package auth

import (
	"ads-httpproxy/internal/config"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestPrincipalDefensiveCopiesAndExpiry(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	p := Principal{Subject: "one", Groups: []string{"staff"}, ExpiresAt: time.Now().Add(time.Hour)}
	BindPrincipal(req, p)
	p.Groups[0] = "admin"
	got, ok := PrincipalFromContext(req.Context())
	require.True(t, ok)
	require.Equal(t, "staff", got.Groups[0])
	got.Groups[0] = "admin"
	got, _ = PrincipalFromContext(req.Context())
	require.Equal(t, "staff", got.Groups[0])
	p.ExpiresAt = time.Now().Add(-time.Second)
	BindPrincipal(req, p)
	_, ok = PrincipalFromContext(req.Context())
	require.False(t, ok)
}
func TestOAuthIntrospectionEnforcesClaims(t *testing.T) {
	claims := map[string]any{"active": true, "sub": "user-1", "username": "alice", "iss": "https://issuer.test", "aud": []string{"gateway"}, "scope": "read write", "exp": time.Now().Add(time.Hour).Unix(), "groups": []string{"staff"}, "tenant": "one", "device_id": "device-1"}
	var mu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "POST", r.Method)
		require.NoError(t, r.ParseForm())
		require.Equal(t, "token", r.Form.Get("token"))
		u, p, ok := r.BasicAuth()
		require.True(t, ok)
		require.Equal(t, "client", u)
		require.Equal(t, "secret", p)
		mu.Lock()
		defer mu.Unlock()
		json.NewEncoder(w).Encode(claims)
	}))
	defer server.Close()
	a, err := NewOAuth2Authenticator(&config.OAuth2Config{IntrospectionURL: server.URL, ClientID: "client", ClientSecret: "secret", Audience: "gateway", Issuer: "https://issuer.test", RequiredScopes: []string{"write"}, RequireExpiry: true}, zap.NewNop())
	require.NoError(t, err)
	request := func() *http.Request {
		r := httptest.NewRequest("GET", "/", nil)
		r.Header.Set("Authorization", "Bearer token")
		return r
	}
	req := request()
	ok, user, _, err := a.Authenticate(req)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, "alice", user)
	p, ok := PrincipalFromContext(req.Context())
	require.True(t, ok)
	require.Equal(t, "one", p.Tenant)
	require.Equal(t, "device-1", p.DeviceID)
	require.Equal(t, []string{"staff"}, p.Groups)
	for _, tc := range []struct {
		key   string
		value any
	}{{"active", false}, {"aud", "other"}, {"iss", "https://other.test"}, {"scope", "read"}, {"exp", time.Now().Add(-time.Second).Unix()}, {"exp", 0}, {"nbf", time.Now().Add(time.Hour).Unix()}, {"sub", ""}} {
		mu.Lock()
		old, existed := claims[tc.key]
		claims[tc.key] = tc.value
		mu.Unlock()
		ok, _, _, err := a.Authenticate(request())
		require.NoError(t, err)
		require.False(t, ok, tc.key)
		mu.Lock()
		if existed {
			claims[tc.key] = old
		} else {
			delete(claims, tc.key)
		}
		mu.Unlock()
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req = request().WithContext(ctx)
	ok, _, _, _ = a.Authenticate(req)
	require.False(t, ok)
}

type oidcFixture struct {
	server           *httptest.Server
	key              *rsa.PrivateKey
	mu               sync.Mutex
	nonce, challenge string
	badNonce         bool
	exchanges        int
}

func newOIDCFixture(t *testing.T) *oidcFixture {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	f := &oidcFixture{key: key}
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			json.NewEncoder(w).Encode(map[string]any{"issuer": f.server.URL, "authorization_endpoint": f.server.URL + "/authorize", "token_endpoint": f.server.URL + "/token", "jwks_uri": f.server.URL + "/keys", "id_token_signing_alg_values_supported": []string{"RS256"}})
		case "/keys":
			json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{"kty": "RSA", "kid": "test", "alg": "RS256", "use": "sig", "n": base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()), "e": "AQAB"}}})
		case "/token":
			require.NoError(t, r.ParseForm())
			f.mu.Lock()
			defer f.mu.Unlock()
			f.exchanges++
			challenge := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
			require.Equal(t, f.challenge, base64.RawURLEncoding.EncodeToString(challenge[:]))
			require.Equal(t, "code", r.Form.Get("code"))
			nonce := f.nonce
			if f.badNonce {
				nonce = "wrong"
			}
			token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{"iss": f.server.URL, "aud": "client", "sub": "subject-1", "exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(), "nonce": nonce, "groups": []string{"finance"}, "tenant": "company", "device_id": "managed-1", "amr": []string{"pwd", "mfa"}, "acr": "strong", "auth_time": time.Now().Unix()})
			token.Header["kid"] = "test"
			signed, err := token.SignedString(key)
			require.NoError(t, err)
			json.NewEncoder(w).Encode(map[string]any{"access_token": "access", "token_type": "Bearer", "expires_in": 3600, "id_token": signed, "scope": "openid profile"})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.server.Close)
	return f
}
func gatewayRequest(method, target string) *http.Request {
	r := httptest.NewRequest(method, target, nil)
	r.Host = "gateway.test"
	return r
}
func startOIDC(t *testing.T, a *OIDCAuthenticator, f *oidcFixture) (string, *http.Cookie) {
	t.Helper()
	w := httptest.NewRecorder()
	require.True(t, a.HandleBrowser(w, gatewayRequest("GET", "/auth/login?return=%2Fapp")))
	require.Equal(t, 302, w.Code)
	location, err := url.Parse(w.Header().Get("Location"))
	require.NoError(t, err)
	require.Equal(t, "S256", location.Query().Get("code_challenge_method"))
	require.NotEmpty(t, location.Query().Get("nonce"))
	f.mu.Lock()
	f.nonce = location.Query().Get("nonce")
	f.challenge = location.Query().Get("code_challenge")
	f.mu.Unlock()
	return location.Query().Get("state"), w.Result().Cookies()[0]
}
func TestOIDCBrowserFlowPKCEStateNonceSessionAndRevocation(t *testing.T) {
	f := newOIDCFixture(t)
	a, err := NewOIDCAuthenticator(&config.OIDCConfig{Issuer: f.server.URL, ClientID: "client", ClientSecret: "secret", RedirectURL: "https://gateway.test/auth/callback"}, zap.NewNop())
	require.NoError(t, err)
	state, cookie := startOIDC(t, a, f)
	req := gatewayRequest("GET", "/auth/callback?code=code&state="+state)
	w := httptest.NewRecorder()
	a.HandleBrowser(w, req)
	require.Equal(t, 400, w.Code)
	req.AddCookie(cookie)
	w = httptest.NewRecorder()
	a.HandleBrowser(w, req)
	require.Equal(t, 303, w.Code)
	require.Equal(t, "/app", w.Header().Get("Location"))
	var session *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == sessionCookie {
			session = c
		}
	}
	require.NotNil(t, session)
	require.True(t, session.Secure)
	require.True(t, session.HttpOnly)
	require.Empty(t, session.Domain)
	app := gatewayRequest("GET", "/app")
	app.AddCookie(session)
	ok, user, _, err := a.Authenticate(app)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, "subject-1", user)
	p, ok := PrincipalFromContext(app.Context())
	require.True(t, ok)
	require.Equal(t, []string{"finance"}, p.Groups)
	require.Equal(t, "company", p.Tenant)
	require.Equal(t, "managed-1", p.DeviceID)
	require.Contains(t, p.AMR, "mfa")
	replay := httptest.NewRecorder()
	a.HandleBrowser(replay, req)
	require.Equal(t, 400, replay.Code)
	absolute := httptest.NewRequest("GET", "https://gateway.test/app", nil)
	absolute.AddCookie(session)
	ok, _, _, _ = a.Authenticate(absolute)
	require.False(t, ok)
	require.Equal(t, 1, a.RevokeSubject("subject-1"))
	ok, _, _, _ = a.Authenticate(app)
	require.False(t, ok)
	state, cookie = startOIDC(t, a, f)
	f.mu.Lock()
	f.badNonce = true
	f.mu.Unlock()
	req = gatewayRequest("GET", "/auth/callback?code=code&state="+state)
	req.AddCookie(cookie)
	w = httptest.NewRecorder()
	a.HandleBrowser(w, req)
	require.Equal(t, 401, w.Code)
}
func TestBrowserHostLogoutAndReturnValidation(t *testing.T) {
	root, _ := url.Parse("https://gateway.test/auth/callback")
	s := newBrowserSessions(root, 1, time.Minute)
	r := gatewayRequest("GET", "/")
	w := httptest.NewRecorder()
	require.NoError(t, s.create(w, r, Principal{Subject: "one", Username: "alice"}))
	cookie := w.Result().Cookies()[0]
	logout := gatewayRequest("POST", "/auth/logout")
	logout.AddCookie(cookie)
	w = httptest.NewRecorder()
	s.logout(w, logout)
	require.Equal(t, 403, w.Code)
	_, ok := s.get(logout)
	require.True(t, ok)
	logout.Header.Set("Origin", "https://gateway.test")
	w = httptest.NewRecorder()
	s.logout(w, logout)
	require.Equal(t, 204, w.Code)
	_, ok = s.get(logout)
	require.False(t, ok)
	for _, raw := range []string{"https://evil.test/", "//evil.test/", "/\\evil.test/", "/bad\nlocation", ""} {
		require.Equal(t, "/", localReturnPath(raw))
	}
	require.Equal(t, "/app?a=1", localReturnPath("/app?a=1"))
}
func TestOAuthRejectsPlaintextRemoteEndpoint(t *testing.T) {
	_, err := NewOAuth2Authenticator(&config.OAuth2Config{IntrospectionURL: "http://identity.example/token"}, zap.NewNop())
	require.Error(t, err)
}
func TestOIDCDoesNotAcceptIDTokenAsAccessTokenByDefault(t *testing.T) {
	f := newOIDCFixture(t)
	a, err := NewOIDCAuthenticator(&config.OIDCConfig{Issuer: f.server.URL, ClientID: "client"}, zap.NewNop())
	require.NoError(t, err)
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer ignored")
	ok, _, _, err := a.Authenticate(r)
	require.NoError(t, err)
	require.False(t, ok)
}
func TestOAuthIntrospectionDoesNotFollowRedirects(t *testing.T) {
	called := false
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	defer target.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, 307) }))
	defer origin.Close()
	a, err := NewOAuth2Authenticator(&config.OAuth2Config{IntrospectionURL: origin.URL}, zap.NewNop())
	require.NoError(t, err)
	r := httptest.NewRequest("GET", "/", strings.NewReader(""))
	r.Header.Set("Authorization", "Bearer secret")
	ok, _, _, _ := a.Authenticate(r)
	require.False(t, ok)
	require.False(t, called)
}
