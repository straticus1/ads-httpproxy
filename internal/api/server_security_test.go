package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"ads-httpproxy/internal/config"
	"ads-httpproxy/pkg/logging"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestHandleConfigRedactsSecrets(t *testing.T) {
	logging.Logger = zap.NewNop()
	cfg := config.NewConfig()
	cfg.ApiSecret = "top-secret"
	cfg.ApiUsers = map[string]string{"admin": "password123"}
	cfg.Auth.Users = map[string]string{"proxy-user": "proxy-password"}
	s := NewServer(cfg, nil, nil)

	rec := httptest.NewRecorder()
	s.handleConfig(rec, httptest.NewRequest(http.MethodGet, "/config", nil))

	require.Equal(t, http.StatusOK, rec.Code)
	require.NotContains(t, rec.Body.String(), "top-secret")
	require.NotContains(t, rec.Body.String(), "password123")
	require.NotContains(t, rec.Body.String(), "proxy-password")
}

func TestHandleConfigRejectsUnsafeLiveReplacement(t *testing.T) {
	logging.Logger = zap.NewNop()
	cfg := config.NewConfig()
	s := NewServer(cfg, nil, nil)
	body := `{"addr":":8181","api_secret":"replacement"}`

	rec := httptest.NewRecorder()
	s.handleConfig(rec, httptest.NewRequest(http.MethodPost, "/config", strings.NewReader(body)))

	require.Equal(t, http.StatusNotImplemented, rec.Code)
	require.Equal(t, ":8080", cfg.Addr)
}

func TestConfigRedactsSecretsInsideArrays(t *testing.T) {
	cfg := config.NewConfig()
	cfg.Plugins = &config.PluginConfig{Configurations: map[string]any{"example": []any{map[string]any{"password": "nested-secret", "children": []any{map[string]any{"api_key": "nested-key"}}}}}}
	value, err := redactedConfig(cfg)
	require.NoError(t, err)
	require.NotContains(t, fmt.Sprint(value), "nested-secret")
	require.NotContains(t, fmt.Sprint(value), "nested-key")
	require.Contains(t, fmt.Sprint(value), "[REDACTED]")
}
