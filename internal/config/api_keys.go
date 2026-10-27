package config

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

type ControlPlaneConfig struct {
	Audience   string            `json:"audience" yaml:"audience"`
	StateFile  string            `json:"state_file" yaml:"state_file"`
	PublicKeys map[string]string `json:"public_keys" yaml:"public_keys"`
}

func (c ControlPlaneConfig) Validate() error {
	if c.Audience == "" || len(c.Audience) > 256 || c.StateFile == "" || len(c.PublicKeys) == 0 || len(c.PublicKeys) > 32 {
		return fmt.Errorf("control_plane requires audience, state_file and 1..32 trusted public_keys")
	}
	for id, encoded := range c.PublicKeys {
		key, err := base64.StdEncoding.DecodeString(encoded)
		if id == "" || err != nil || len(key) != 32 {
			return fmt.Errorf("invalid control-plane public key %q", id)
		}
	}
	return nil
}

// ScopedAPIKey stores a digest of a high-entropy credential, never its plaintext.
// Scopes deliberately exclude global administration and policy mutation.
type ScopedAPIKey struct {
	ID     string   `json:"id" yaml:"id"`
	SHA256 string   `json:"sha256" yaml:"sha256"`
	Tenant string   `json:"tenant" yaml:"tenant"`
	Scopes []string `json:"scopes" yaml:"scopes"`
}

func validateAPIKeys(keys []ScopedAPIKey) error {
	if len(keys) > 1000 {
		return fmt.Errorf("api_keys exceeds 1000 credentials")
	}
	ids, hashes := map[string]bool{}, map[string]bool{}
	for _, k := range keys {
		hash, err := hex.DecodeString(k.SHA256)
		if k.ID == "" || len(k.ID) > 128 || k.Tenant == "" || len(k.Tenant) > 256 || strings.TrimSpace(k.Tenant) != k.Tenant || err != nil || len(hash) != 32 || len(k.Scopes) == 0 {
			return fmt.Errorf("api_keys requires id, tenant, SHA-256 digest and scopes")
		}
		canonical := strings.ToLower(k.SHA256)
		if ids[k.ID] || hashes[canonical] {
			return fmt.Errorf("api_keys contains duplicate id or credential")
		}
		ids[k.ID], hashes[canonical] = true, true
		for _, scope := range k.Scopes {
			if scope != "findings:read" && scope != "ai:explain" {
				return fmt.Errorf("unsupported API key scope %q", scope)
			}
		}
	}
	return nil
}
