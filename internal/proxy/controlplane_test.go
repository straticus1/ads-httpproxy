package proxy

import (
	"ads-httpproxy/internal/config"
	"ads-httpproxy/internal/controlplane"
	"ads-httpproxy/internal/policy"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func TestSignedReleaseChangesLiveGatewayAndRestores(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	cfg := config.NewConfig()
	cfg.ApiSecret = "test-admin"
	cfg.ControlPlane = &config.ControlPlaneConfig{Audience: "fixture", StateFile: filepath.Join(t.TempDir(), "bundle.json"), PublicKeys: map[string]string{"k": base64.StdEncoding.EncodeToString(pub)}}
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("origin")) }))
	t.Cleanup(origin.Close)
	s, client, _ := platformProxy(t, cfg)
	status, _, _ := platformRequest(t, client, "GET", origin.URL, nil)
	require.Equal(t, 403, status, "unenrolled node must deny")
	env, err := controlplane.Sign("k", priv, controlplane.Release{SchemaVersion: "v1", Audience: "fixture", Revision: 1, IssuedAt: time.Now().Add(-time.Minute), ExpiresAt: time.Now().Add(time.Hour), DefaultEffect: "block", Policies: []*policy.Policy{{ID: "get", Effect: "allow", Condition: `request.method == "GET"`}}})
	require.NoError(t, err)
	data, err := json.Marshal(env)
	require.NoError(t, err)
	r := httptest.NewRequest("PUT", "/api/control-plane/policy", bytes.NewReader(data))
	r.Header.Set("X-API-Key", cfg.ApiSecret)
	w := httptest.NewRecorder()
	s.apiServer.Handler().ServeHTTP(w, r)
	require.Equal(t, 200, w.Code, w.Body.String())
	status, _, body := platformRequest(t, client, "GET", origin.URL, nil)
	require.Equal(t, 200, status)
	require.Equal(t, "origin", body)
	status, _, _ = platformRequest(t, client, "POST", origin.URL, nil)
	require.Equal(t, 403, status)
	_, restored, _ := platformProxy(t, cfg)
	status, _, _ = platformRequest(t, restored, "GET", origin.URL, nil)
	require.Equal(t, 200, status)
	status, _, _ = platformRequest(t, restored, "POST", origin.URL, nil)
	require.Equal(t, 403, status)
}
