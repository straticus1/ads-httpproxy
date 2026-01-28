package auth

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"ads-httpproxy/internal/config"

	"github.com/coreos/go-oidc/v3/oidc"
	"go.uber.org/zap"
)

// OIDCAuthenticator implements OpenID Connect authentication
type OIDCAuthenticator struct {
	cfg      *config.OIDCConfig
	logger   *zap.Logger
	provider *oidc.Provider
	verifier *oidc.IDTokenVerifier
}

func NewOIDCAuthenticator(cfg *config.OIDCConfig, logger *zap.Logger) (*OIDCAuthenticator, error) {
	if cfg == nil {
		return nil, errors.New("oidc config missing")
	}

	ctx := context.Background()
	// Skip provider discovery if issuer not set (test mode), but usually required.
	if cfg.Issuer == "" {
		return nil, errors.New("oidc issuer required")
	}

	provider, err := oidc.NewProvider(ctx, cfg.Issuer)
	if err != nil {
		return nil, err
	}

	oidcConfig := &oidc.Config{
		ClientID: cfg.ClientID,
	}
	verifier := provider.Verifier(oidcConfig)

	return &OIDCAuthenticator{
		cfg:      cfg,
		logger:   logger,
		provider: provider,
		verifier: verifier,
	}, nil
}

func (a *OIDCAuthenticator) Challenge(req *http.Request) (string, error) {
	// For API Clients: Return Bearer challenge
	return "Bearer realm=\"ads-proxy\", scope=\"openid\"", nil
}

func (a *OIDCAuthenticator) Authenticate(req *http.Request) (bool, string, string, error) {
	authHeader := req.Header.Get("Proxy-Authorization")
	// Fallback to Authorization for Reverse Proxy mode or direct Gateway use
	if authHeader == "" {
		authHeader = req.Header.Get("Authorization")
	}

	if authHeader == "" {
		return false, "", "", nil
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return false, "", "", nil
	}

	tokenStr := parts[1]
	ctx := req.Context()
	idToken, err := a.verifier.Verify(ctx, tokenStr)
	if err != nil {
		a.logger.Debug("failed to verify oidc token", zap.Error(err))
		return false, "", "", nil
	}

	// Extract claims
	var claims struct {
		Email string `json:"email"`
		Sub   string `json:"sub"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return false, "", "", errors.New("failed to parse claims")
	}

	user := claims.Email
	if user == "" {
		user = claims.Sub
	}

	return true, user, "", nil
}
