package api

import (
	"ads-httpproxy/internal/config"
	"ads-httpproxy/internal/controlplane"
	"ads-httpproxy/internal/policy"
	"ads-httpproxy/pkg/logging"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func TestPolicyBundleRequiresAdministratorAndSignature(t *testing.T) {
	logging.Logger = zap.NewNop()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	e, err := policy.NewEngine()
	require.NoError(t, err)
	m, err := controlplane.New(controlplane.Config{Audience: "test", StateFile: filepath.Join(t.TempDir(), "state"), PublicKeys: map[string]string{"k": base64.StdEncoding.EncodeToString(pub)}}, e)
	require.NoError(t, err)
	cfg := config.NewConfig()
	cfg.ApiSecret = "admin-test"
	s := NewServer(cfg, nil, nil)
	s.SetControlPlane(m)
	h := s.Handler()
	env, err := controlplane.Sign("k", priv, controlplane.Release{SchemaVersion: "v1", Audience: "test", Revision: 1, IssuedAt: time.Now().Add(-time.Minute), ExpiresAt: time.Now().Add(time.Hour), DefaultEffect: "block"})
	require.NoError(t, err)
	data, err := json.Marshal(env)
	require.NoError(t, err)
	for _, test := range []struct {
		key  string
		body []byte
		code int
	}{{"", data, 401}, {"wrong", data, 401}, {"admin-test", []byte(`{}`), 409}, {"admin-test", data, 200}, {"admin-test", data, 409}} {
		r := httptest.NewRequest("PUT", "/api/control-plane/policy", bytes.NewReader(test.body))
		r.Header.Set("X-API-Key", test.key)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		require.Equal(t, test.code, w.Code, w.Body.String())
	}
	require.Equal(t, uint64(1), m.Status().Revision)
}
