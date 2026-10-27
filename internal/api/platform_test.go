package api

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ads-httpproxy/internal/adaptive"
	"ads-httpproxy/internal/ai"
	"ads-httpproxy/internal/analysis"
	"ads-httpproxy/internal/config"
	"ads-httpproxy/pkg/logging"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestPlatformAPIStartAndShutdownOwnListener(t *testing.T) {
	cfg := config.NewConfig()
	cfg.ApiAddr = "127.0.0.1:0"
	s := NewServer(cfg, nil, nil)
	require.NoError(t, s.Start())
	t.Cleanup(func() { _ = s.Shutdown(context.Background()) })
	address := s.listener.Addr().String()
	client := &http.Client{Timeout: time.Second}
	resp, err := client.Get("http://" + address + "/healthz")
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, 200, resp.StatusCode)
	require.Error(t, s.Start())
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	require.NoError(t, s.Shutdown(ctx))
	conn, err := net.DialTimeout("tcp", address, time.Second)
	if conn != nil {
		conn.Close()
	}
	require.Error(t, err, "Shutdown must close the bound listener")
}

func TestPlatformAPIRejectsMalformedMTLSBeforeListening(t *testing.T) {
	fixture := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	cert := fixture.TLS.Certificates[0]
	fixture.Close()
	dir := t.TempDir()
	certPath, keyPath, caPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem"), filepath.Join(dir, "ca.pem")
	key, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}), 0600))
	require.NoError(t, os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0600))
	require.NoError(t, os.WriteFile(caPath, []byte("invalid certificate"), 0600))
	for _, tc := range []struct{ name, cert, key, ca string }{
		{"client CA without TLS", "", "", caPath},
		{"invalid CA", certPath, keyPath, caPath},
		{"missing key", certPath, "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.NewConfig()
			cfg.ApiAddr = "127.0.0.1:0"
			cfg.ApiCert = tc.cert
			cfg.ApiPrivKey = tc.key
			cfg.ApiClientCA = tc.ca
			s := NewServer(cfg, nil, nil)
			require.Error(t, s.Start())
			require.Nil(t, s.listener)
		})
	}
}

func TestPlatformAPIAuthenticationValidationAndPolicyConflicts(t *testing.T) {
	logging.Logger = zap.NewNop()
	cfg := config.NewConfig()
	cfg.ApiSecret = "test-key"
	cfg.ApiRateLimit = 0
	cfg.AI = &ai.Config{Enabled: true}
	m, err := analysis.New(analysis.Config{Enabled: true}, nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, m.Close(context.Background())) })
	e, err := adaptive.New(adaptive.Config{Enabled: true, Mode: "shadow"})
	require.NoError(t, err)
	s := NewServer(cfg, nil, nil)
	s.SetPlatform(m, e)
	s.SetIdentityRevoker(func(subject string) int {
		if subject == "alice" {
			return 2
		}
		return 0
	})
	server := httptest.NewServer(s.Handler())
	t.Cleanup(server.Close)
	request := func(method, path, body string, authorized bool) (int, http.Header, string) {
		t.Helper()
		req, err := http.NewRequest(method, server.URL+path, strings.NewReader(body))
		require.NoError(t, err)
		if authorized {
			req.Header.Set("X-API-Key", "test-key")
		}
		resp, err := server.Client().Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		b, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		return resp.StatusCode, resp.Header, string(b)
	}
	for _, path := range []string{"/api/analysis/findings", "/api/analysis/stats", "/api/adaptive/policy", "/api/adaptive/preview", "/api/adaptive/rollback", "/api/ai/explain", "/api/identity/revoke"} {
		code, _, _ := request("GET", path, "", false)
		require.Equal(t, 401, code, path)
	}
	code, headers, _ := request("GET", "/api/adaptive/policy", "", true)
	require.Equal(t, 200, code)
	require.Equal(t, "no-store", headers.Get("Cache-Control"))
	update := `{"expected_version":1,"mode":"enforce","rules":[{"id":"deny","host":"example.com","action":"block"}]}`
	code, _, _ = request("PUT", "/api/adaptive/policy", update, true)
	require.Equal(t, 200, code)
	require.EqualValues(t, 2, e.Snapshot().Version)
	code, _, _ = request("PUT", "/api/adaptive/policy", update, true)
	require.Equal(t, 409, code)
	for _, body := range []string{`{"expected_version":2,"mode":"invalid"}`, `{"expected_version":2,"mode":"shadow","unexpected":true}`, `{"expected_version":2,"mode":"shadow"} {}`, strings.Repeat(" ", 64<<10) + `{}`} {
		code, _, _ = request("PUT", "/api/adaptive/policy", body, true)
		require.Equal(t, 400, code)
	}
	require.EqualValues(t, 2, e.Snapshot().Version)
	code, _, body := request("POST", "/api/adaptive/preview", `{"host":"example.com"}`, true)
	require.Equal(t, 200, code)
	require.Contains(t, body, `"blocked":true`)
	code, _, _ = request("POST", "/api/adaptive/rollback", `{"expected_version":2,"target_version":1}`, true)
	require.Equal(t, 200, code)
	require.EqualValues(t, 3, e.Snapshot().Version)
	require.Equal(t, "shadow", e.Snapshot().Mode)
	code, _, _ = request("POST", "/api/adaptive/rollback", `{"expected_version":2,"target_version":1}`, true)
	require.Equal(t, 409, code)
	code, _, body = request("POST", "/api/identity/revoke", `{"subject":"alice"}`, true)
	require.Equal(t, 200, code)
	require.Contains(t, body, `"revoked_sessions":2`)
	code, _, _ = request("POST", "/api/identity/revoke", `{}`, true)
	require.Equal(t, 400, code)
	code, _, _ = request("GET", "/api/analysis/findings?limit=1001", "", true)
	require.Equal(t, 400, code)
	code, _, _ = request("POST", "/api/analysis/stats", `{}`, true)
	require.Equal(t, 405, code)
	code, _, body = request("POST", "/api/ai/explain", `{}`, true)
	require.Equal(t, 200, code)
	require.Contains(t, body, `"source":"local"`)
}
