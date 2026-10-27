package auth

import (
	"ads-httpproxy/internal/config"
	"encoding/json"
	"errors"
	"go.uber.org/zap"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// OAuth2Authenticator verifies access tokens with an RFC 7662 introspection endpoint.
type OAuth2Authenticator struct {
	cfg    *config.OAuth2Config
	logger *zap.Logger
	client *http.Client
}

func NewOAuth2Authenticator(cfg *config.OAuth2Config, logger *zap.Logger) (*OAuth2Authenticator, error) {
	if cfg == nil {
		return nil, errors.New("oauth2 config missing")
	}
	if _, err := config.IdentityURL(cfg.IntrospectionURL); err != nil {
		return nil, err
	}
	if (cfg.ClientID == "") != (cfg.ClientSecret == "") {
		return nil, errors.New("oauth2 client ID and secret must be supplied together")
	}
	copy := *cfg
	copy.RequiredScopes = append([]string(nil), cfg.RequiredScopes...)
	return &OAuth2Authenticator{cfg: &copy, logger: logger, client: &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}
func (a *OAuth2Authenticator) Challenge(*http.Request) (string, error) {
	return `Bearer realm="ads-proxy"`, nil
}
func (a *OAuth2Authenticator) Authenticate(req *http.Request) (bool, string, string, error) {
	token := bearerToken(req)
	if token == "" {
		return false, "", "", nil
	}
	data := url.Values{"token": {token}, "token_type_hint": {"access_token"}}
	introReq, err := http.NewRequestWithContext(req.Context(), "POST", a.cfg.IntrospectionURL, strings.NewReader(data.Encode()))
	if err != nil {
		return false, "", "", err
	}
	introReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if a.cfg.ClientID != "" {
		introReq.SetBasicAuth(a.cfg.ClientID, a.cfg.ClientSecret)
	}
	resp, err := a.client.Do(introReq)
	if err != nil {
		return false, "", "", nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, "", "", nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, (64<<10)+1))
	if err != nil || len(body) > 64<<10 {
		return false, "", "", errors.New("invalid introspection response")
	}
	var result struct {
		DeviceID  string          `json:"device_id"`
		Active    bool            `json:"active"`
		Username  string          `json:"username"`
		Sub       string          `json:"sub"`
		Issuer    string          `json:"iss"`
		Audience  json.RawMessage `json:"aud"`
		Scope     string          `json:"scope"`
		Expiry    int64           `json:"exp"`
		NotBefore int64           `json:"nbf"`
		Groups    []string        `json:"groups"`
		Tenant    string          `json:"tenant"`
		AMR       []string        `json:"amr"`
		ACR       string          `json:"acr"`
		AuthTime  int64           `json:"auth_time"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return false, "", "", errors.New("invalid introspection response")
	}
	now := time.Now().Unix()
	if !result.Active || result.Sub == "" || result.Expiry != 0 && result.Expiry <= now || result.NotBefore > now || a.cfg.RequireExpiry && result.Expiry == 0 {
		return false, "", "", nil
	}
	if a.cfg.Issuer != "" && result.Issuer != a.cfg.Issuer {
		return false, "", "", nil
	}
	if a.cfg.Audience != "" && !audienceContains(result.Audience, a.cfg.Audience) {
		return false, "", "", nil
	}
	scopes := strings.Fields(result.Scope)
	for _, required := range a.cfg.RequiredScopes {
		found := false
		for _, scope := range scopes {
			if scope == required {
				found = true
			}
		}
		if !found {
			return false, "", "", nil
		}
	}
	p := Principal{DeviceID: result.DeviceID, Subject: result.Sub, Username: result.Username, Issuer: result.Issuer, Groups: result.Groups, Scopes: scopes, Tenant: result.Tenant, AMR: result.AMR, ACR: result.ACR}
	if p.Issuer == "" {
		p.Issuer = a.cfg.IntrospectionURL
	}
	if p.Username == "" {
		p.Username = p.Subject
	}
	if result.Expiry != 0 {
		p.ExpiresAt = time.Unix(result.Expiry, 0)
	}
	if result.AuthTime != 0 {
		p.AuthTime = time.Unix(result.AuthTime, 0)
	}
	BindPrincipal(req, p)
	return true, p.Username, "", nil
}
func audienceContains(raw json.RawMessage, want string) bool {
	var values []string
	if json.Unmarshal(raw, &values) != nil {
		var value string
		if json.Unmarshal(raw, &value) != nil {
			return false
		}
		values = []string{value}
	}
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
