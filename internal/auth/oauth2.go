package auth

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"ads-httpproxy/internal/config"

	"go.uber.org/zap"
)

// OAuth2Authenticator implements RFC 7662 Token Introspection
type OAuth2Authenticator struct {
	cfg    *config.OAuth2Config
	logger *zap.Logger
	client *http.Client
}

func NewOAuth2Authenticator(cfg *config.OAuth2Config, logger *zap.Logger) (*OAuth2Authenticator, error) {
	if cfg == nil || cfg.IntrospectionURL == "" {
		return nil, errors.New("oauth2 introspection_url is required")
	}

	return &OAuth2Authenticator{
		cfg:    cfg,
		logger: logger,
		client: &http.Client{Timeout: 5 * time.Second},
	}, nil
}

func (a *OAuth2Authenticator) Challenge(req *http.Request) (string, error) {
	return "Bearer realm=\"ads-proxy\"", nil
}

func (a *OAuth2Authenticator) Authenticate(req *http.Request) (bool, string, string, error) {
	authHeader := req.Header.Get("Proxy-Authorization")
	if authHeader == "" {
		authHeader = req.Header.Get("Authorization")
	}

	if authHeader == "" {
		return false, "", "", nil
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return false, "", "", nil
	}

	token := parts[1]

	data := url.Values{}
	data.Set("token", token)

	introReq, err := http.NewRequest("POST", a.cfg.IntrospectionURL, strings.NewReader(data.Encode()))
	if err != nil {
		return false, "", "", err
	}

	introReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// If ClientAuth is required (e.g. Authentik backend client access)
	if a.cfg.ClientID != "" && a.cfg.ClientSecret != "" {
		introReq.SetBasicAuth(a.cfg.ClientID, a.cfg.ClientSecret)
	}

	resp, err := a.client.Do(introReq)
	if err != nil {
		a.logger.Debug("failed to contact introspection endpoint", zap.Error(err))
		return false, "", "", nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, "", "", nil
	}

	var result struct {
		Active   bool   `json:"active"`
		Username string `json:"username,omitempty"`
		Sub      string `json:"sub,omitempty"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false, "", "", errors.New("failed to parse introspection response")
	}

	if !result.Active {
		return false, "", "", nil
	}

	user := result.Username
	if user == "" {
		user = result.Sub
	}
	if user == "" {
		user = "oauth2-user"
	}

	return true, user, "", nil
}
