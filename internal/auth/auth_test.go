package auth

import (
	"testing"

	"ads-httpproxy/internal/config"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

func TestNewAuthenticator(t *testing.T) {
	logger := zap.NewNop()

	t.Run("OIDC", func(t *testing.T) {
		cfg := &config.AuthConfig{
			Mechanism: "oidc",
			OIDC: &config.OIDCConfig{
				Issuer:   "https://accounts.google.com",
				ClientID: "test-client",
			},
		}
		// Note: This will try to connect to Google in NewOIDCAuthenticator.
		// For unit test without network, we might expect failure or need to mock.
		// However, NewOIDCAuthenticator connects immediately.
		// Let's just check invalid config for now to avoid network deps in unit test.
		cfg.OIDC = nil
		_, err := NewAuthenticator(cfg, logger)
		assert.Error(t, err)
	})

	t.Run("SAML", func(t *testing.T) {
		// Test config validation
		cfg := &config.AuthConfig{
			Mechanism: "saml",
			SAML:      nil, // Missing config
		}
		_, err := NewAuthenticator(cfg, logger)
		assert.Error(t, err)
	})

	t.Run("None", func(t *testing.T) {
		cfg := &config.AuthConfig{
			Mechanism: "none",
		}
		auth, err := NewAuthenticator(cfg, logger)
		assert.NoError(t, err)
		assert.Nil(t, auth)
	})
}
