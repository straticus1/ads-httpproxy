// Package controlplane accepts signed policy releases outside the request path.
// It is an ingestion boundary, not a fleet scheduler or enrollment service.
package controlplane

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"ads-httpproxy/internal/config"
	"ads-httpproxy/internal/policy"
)

const MaxEnvelopeBytes = 2 << 20

var errPersistenceUncertain = errors.New("policy file renamed but directory sync failed; restart required before further updates")

type Config = config.ControlPlaneConfig
type Envelope struct {
	KeyID     string `json:"key_id"`
	Payload   []byte `json:"payload"`
	Signature []byte `json:"signature"`
}
type Release struct {
	SchemaVersion string           `json:"schema_version"`
	Audience      string           `json:"audience"`
	Revision      uint64           `json:"revision"`
	IssuedAt      time.Time        `json:"issued_at"`
	ExpiresAt     time.Time        `json:"expires_at"`
	DefaultEffect string           `json:"default_effect"`
	Policies      []*policy.Policy `json:"policies"`
}
type Status struct {
	UpdateError   string    `json:"update_error,omitempty"`
	Revision      uint64    `json:"revision"`
	PolicyVersion uint64    `json:"policy_version"`
	ExpiresAt     time.Time `json:"expires_at"`
	Stale         bool      `json:"stale"`
}
type Manager struct {
	mu     sync.Mutex
	cfg    Config
	keys   map[string]ed25519.PublicKey
	engine *policy.Engine
	status Status
}

func Validate(c Config) error {
	return c.Validate()
}
func New(c Config, e *policy.Engine) (*Manager, error) {
	if err := Validate(c); err != nil {
		return nil, err
	}
	m := &Manager{cfg: c, engine: e, keys: map[string]ed25519.PublicKey{}}
	for id, v := range c.PublicKeys {
		key, _ := base64.StdEncoding.DecodeString(v)
		m.keys[id] = key
	}
	f, err := os.Open(c.StateFile)
	if errors.Is(err, os.ErrNotExist) {
		// A node enrolled for signed releases cannot serve under an unsigned
		// default-allow policy while awaiting its first release.
		if _, err := e.Replace(e.Snapshot().Version, nil, "block"); err != nil {
			return nil, err
		}
		return m, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, MaxEnvelopeBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > MaxEnvelopeBytes {
		return nil, errors.New("saved bundle too large")
	}
	var envelope Envelope
	if err := decode(data, &envelope); err != nil {
		return nil, err
	}
	// An expired saved release is still the last known good policy. Signature,
	// audience and contents are revalidated; status exposes staleness explicitly.
	if _, err := m.apply(envelope, true); err != nil {
		return nil, fmt.Errorf("restore policy bundle: %w", err)
	}
	return m, nil
}
func decode(data []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return err
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}
func signingMessage(keyID string, payload []byte) []byte {
	return append([]byte("ads-policy-bundle/v1\x00"+keyID+"\x00"), payload...)
}
func Sign(keyID string, key ed25519.PrivateKey, r Release) (Envelope, error) {
	if len(key) != ed25519.PrivateKeySize {
		return Envelope{}, errors.New("invalid signing key")
	}
	p, err := json.Marshal(r)
	if err != nil {
		return Envelope{}, err
	}
	return Envelope{KeyID: keyID, Payload: p, Signature: ed25519.Sign(key, signingMessage(keyID, p))}, nil
}
func (m *Manager) Apply(e Envelope) (Status, error) { return m.apply(e, false) }
func (m *Manager) Status() Status                   { m.mu.Lock(); defer m.mu.Unlock(); return m.statusLocked() }
func (m *Manager) statusLocked() Status {
	s := m.status
	s.Stale = s.Revision > 0 && !time.Now().Before(s.ExpiresAt)
	return s
}
func (m *Manager) apply(e Envelope, restore bool) (Status, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.status.UpdateError != "" {
		return Status{}, errors.New(m.status.UpdateError)
	}
	key := m.keys[e.KeyID]
	if len(e.Payload) > 1<<20 || len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, signingMessage(e.KeyID, e.Payload), e.Signature) {
		return Status{}, errors.New("invalid bundle signature or size")
	}
	var release Release
	if err := decode(e.Payload, &release); err != nil {
		return Status{}, fmt.Errorf("invalid bundle payload: %w", err)
	}
	now := time.Now()
	if release.SchemaVersion != "v1" || release.Audience != m.cfg.Audience || release.Revision == 0 || release.Revision <= m.status.Revision || release.IssuedAt.IsZero() || release.IssuedAt.After(now.Add(time.Minute)) || !release.ExpiresAt.After(release.IssuedAt) || (!restore && !release.ExpiresAt.After(now)) {
		return Status{}, errors.New("invalid bundle schema, audience, revision or validity window")
	}
	encoded, err := json.Marshal(e)
	if err != nil {
		return Status{}, err
	}
	version, err := m.engine.ReplaceWithPersist(m.engine.Snapshot().Version, release.Policies, release.DefaultEffect, func(uint64) error {
		if restore {
			return nil
		}
		return save(m.cfg.StateFile, encoded)
	})
	if err != nil {
		if errors.Is(err, errPersistenceUncertain) {
			m.status.UpdateError = err.Error()
		}
		return Status{}, err
	}
	m.status = Status{Revision: release.Revision, PolicyVersion: version, ExpiresAt: release.ExpiresAt}
	return m.statusLocked(), nil
}
func save(path string, data []byte) error {
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer directory.Close()
	// Detect unsupported directory synchronization before changing live state.
	if err = directory.Sync(); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".policy-bundle-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if _, err = f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(name, path); err != nil {
		return err
	}
	if err = directory.Sync(); err != nil {
		return fmt.Errorf("%w: %v", errPersistenceUncertain, err)
	}
	return nil
}
