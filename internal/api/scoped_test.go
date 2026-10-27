package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"ads-httpproxy/internal/ai"
	"ads-httpproxy/internal/analysis"
	"ads-httpproxy/internal/config"
	"ads-httpproxy/pkg/logging"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestScopedCredentialTenantIsolation(t *testing.T) {
	logging.Logger = zap.NewNop()
	cfg := config.NewConfig()
	cfg.ApiSecret = ""
	digest := sha256.Sum256([]byte("tenant-a-credential"))
	cfg.APIKeys = []config.ScopedAPIKey{{ID: "a", SHA256: hex.EncodeToString(digest[:]), Tenant: "a", Scopes: []string{"findings:read", "ai:explain"}}}
	cfg.AI = &ai.Config{Enabled: true}
	m, err := analysis.New(analysis.Config{Enabled: true, SampleRate: 1, Workers: 1}, nil)
	require.NoError(t, err)
	for _, tenant := range []string{"a", "b"} {
		require.True(t, m.Submit(analysis.Event{Tenant: tenant, Method: "GET", URL: "https://" + tenant + ".example/", Timestamp: time.Now()}))
	}
	require.NoError(t, m.Close(context.Background()))
	s := NewServer(cfg, nil, nil)
	s.SetPlatform(m, nil)
	h := s.Handler()
	request := func(method, path, body, key string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("X-API-Key", key)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	w := request("GET", "/api/analysis/findings", "", "tenant-a-credential")
	require.Equal(t, 200, w.Code)
	require.Contains(t, w.Body.String(), "a.example")
	require.NotContains(t, w.Body.String(), "b.example")
	for _, path := range []string{"/api/analysis/findings?tenant=b", "/config", "/stats", "/api/analysis/stats", "/metrics"} {
		require.Equal(t, http.StatusForbidden, request("GET", path, "", "tenant-a-credential").Code, path)
	}
	require.Equal(t, 403, request("POST", "/api/ai/explain", `{"tenant":"b"}`, "tenant-a-credential").Code)
	require.Equal(t, 200, request("POST", "/api/ai/explain", `{}`, "tenant-a-credential").Code)
	require.Equal(t, 401, request("GET", "/config", "", "").Code)
	require.Equal(t, 401, request("GET", "/api/analysis/findings", "", "wrong-key").Code)
	for _, path := range []string{"/proxy.pac?tenant=b", "/proxy.pac?user=other"} {
		require.Equal(t, 403, request("GET", path, "", "").Code)
	}
	for _, header := range []string{"X-Tenant-ID", "X-User-ID", "Authorization"} {
		r := httptest.NewRequest("GET", "/proxy.pac", nil)
		r.Header.Set(header, "other")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		require.Equal(t, 403, w.Code)
	}
	require.Equal(t, 200, request("GET", "/proxy.pac", "", "").Code)
}
