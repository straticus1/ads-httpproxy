package controlplane

import (
	"ads-httpproxy/internal/policy"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSignedPolicyReleaseAndRestart(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	cfg := Config{Audience: "fleet-a", StateFile: filepath.Join(t.TempDir(), "bundle.json"), PublicKeys: map[string]string{"key1": base64.StdEncoding.EncodeToString(pub)}}
	e, err := policy.NewEngine()
	require.NoError(t, err)
	m, err := New(cfg, e)
	require.NoError(t, err)
	r := Release{SchemaVersion: "v1", Audience: "fleet-a", Revision: 1, IssuedAt: time.Now().Add(-time.Minute), ExpiresAt: time.Now().Add(time.Hour), DefaultEffect: "block", Policies: []*policy.Policy{{ID: "read", Effect: "allow", Condition: `request.method == "GET"`}}}
	sign := func(r Release) Envelope { v, err := Sign("key1", priv, r); require.NoError(t, err); return v }
	v := sign(r)
	status, err := m.Apply(v)
	require.NoError(t, err)
	require.Equal(t, uint64(1), status.Revision)
	before := e.Snapshot()
	_, err = m.Apply(v)
	require.Error(t, err, "replay must fail")
	r.Revision = 2
	bad := sign(r)
	bad.Payload[0] = '!'
	_, err = m.Apply(bad)
	require.Error(t, err)
	for _, mutate := range []func(*Release){func(r *Release) { r.Audience = "other" }, func(r *Release) { r.ExpiresAt = time.Now().Add(-time.Second) }, func(r *Release) { r.Policies = []*policy.Policy{{ID: "bad", Effect: "allow", Condition: "undefined"}} }} {
		candidate := r
		mutate(&candidate)
		_, err = m.Apply(sign(candidate))
		require.Error(t, err)
	}
	require.Equal(t, before, e.Snapshot())
	e2, err := policy.NewEngine()
	require.NoError(t, err)
	m2, err := New(cfg, e2)
	require.NoError(t, err)
	require.Equal(t, uint64(1), m2.Status().Revision)
	require.Equal(t, before.Policies, e2.Snapshot().Policies)
	_, err = m2.Apply(v)
	require.Error(t, err, "replay after restart must fail")
	_, err = m2.Apply(sign(r))
	require.NoError(t, err)
}

func TestFailedPersistenceKeepsPolicy(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	cfg := Config{Audience: "a", StateFile: filepath.Join(t.TempDir(), "missing", "bundle"), PublicKeys: map[string]string{"k": base64.StdEncoding.EncodeToString(pub)}}
	e, err := policy.NewEngine()
	require.NoError(t, err)
	m, err := New(cfg, e)
	require.NoError(t, err)
	v, err := Sign("k", priv, Release{SchemaVersion: "v1", Audience: "a", Revision: 1, IssuedAt: time.Now().Add(-time.Minute), ExpiresAt: time.Now().Add(time.Hour), DefaultEffect: "block"})
	require.NoError(t, err)
	before := e.Snapshot()
	_, err = m.Apply(v)
	require.Error(t, err)
	require.Equal(t, before, e.Snapshot())
	require.Zero(t, m.Status().Revision)
	require.NoError(t, os.Mkdir(filepath.Dir(cfg.StateFile), 0700))
	_, err = m.Apply(v)
	require.NoError(t, err)
}
