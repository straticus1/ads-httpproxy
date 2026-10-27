// Package access evaluates trusted identity/device requirements at the gateway.
package access

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"sync"
	"time"
)

type Config struct {
	Enabled           bool     `json:"enabled" yaml:"enabled"`
	DefaultEffect     string   `json:"default_effect" yaml:"default_effect"`
	RequireIdentity   bool     `json:"require_identity" yaml:"require_identity"`
	RequireMTLS       bool     `json:"require_mtls" yaml:"require_mtls"`
	RequiredGroups    []string `json:"required_groups" yaml:"required_groups"`
	RequiredScopes    []string `json:"required_scopes" yaml:"required_scopes"`
	RequireMFA        bool     `json:"require_mfa" yaml:"require_mfa"`
	MaxAuthAgeSeconds int      `json:"max_auth_age_seconds" yaml:"max_auth_age_seconds"`
	PostureURL        string   `json:"posture_url" yaml:"posture_url"`
	PostureTokenEnv   string   `json:"posture_token_env" yaml:"posture_token_env"`
}

// Identity contains values already verified by the authentication boundary.
type Identity struct {
	Subject      string    `json:"subject"`
	Issuer       string    `json:"issuer"`
	DeviceID     string    `json:"device_id"`
	Groups       []string  `json:"-"`
	Scopes       []string  `json:"-"`
	AMR          []string  `json:"-"`
	AuthTime     time.Time `json:"-"`
	VerifiedMTLS bool      `json:"-"`
}
type posture struct {
	Compliant bool      `json:"compliant"`
	ExpiresAt time.Time `json:"expires_at"`
}
type Evaluator struct {
	cfg    Config
	client *http.Client
	mu     sync.Mutex
	cache  map[string]posture
}

func Validate(c Config) error {
	if c.DefaultEffect != "" && c.DefaultEffect != "allow" && c.DefaultEffect != "block" {
		return fmt.Errorf("access default_effect must be allow or block")
	}
	if c.MaxAuthAgeSeconds < 0 {
		return fmt.Errorf("access max_auth_age_seconds cannot be negative")
	}
	if c.PostureURL != "" {
		if err := ValidateEndpoint(c.PostureURL); err != nil {
			return err
		}
	}
	return nil
}

// ValidateEndpoint permits cleartext only on an explicit loopback host for local tests/services.
func ValidateEndpoint(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" {
		return fmt.Errorf("invalid service endpoint")
	}
	if u.Scheme == "https" {
		return nil
	}
	ip := net.ParseIP(u.Hostname())
	if u.Scheme == "http" && ip != nil && ip.IsLoopback() {
		return nil
	}
	return fmt.Errorf("service endpoint requires HTTPS (HTTP allowed only on loopback IPs)")
}
func New(c Config) (*Evaluator, error) {
	if err := Validate(c); err != nil {
		return nil, err
	}
	return &Evaluator{cfg: c, client: &http.Client{Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, cache: make(map[string]posture)}, nil
}
func (e *Evaluator) Check(ctx context.Context, id Identity) error {
	if e == nil || !e.cfg.Enabled {
		return nil
	}
	if e.cfg.RequireIdentity && (id.Subject == "" || id.Subject == "anonymous") {
		return fmt.Errorf("verified identity required")
	}
	if e.cfg.RequireMTLS && !id.VerifiedMTLS {
		return fmt.Errorf("verified client certificate required")
	}
	for _, group := range e.cfg.RequiredGroups {
		if !slices.Contains(id.Groups, group) {
			return fmt.Errorf("required group missing")
		}
	}
	for _, scope := range e.cfg.RequiredScopes {
		if !slices.Contains(id.Scopes, scope) {
			return fmt.Errorf("required scope missing")
		}
	}
	if e.cfg.RequireMFA && !slices.Contains(id.AMR, "mfa") {
		return fmt.Errorf("MFA required")
	}
	if e.cfg.MaxAuthAgeSeconds > 0 && (id.AuthTime.IsZero() || time.Since(id.AuthTime) > time.Duration(e.cfg.MaxAuthAgeSeconds)*time.Second || id.AuthTime.After(time.Now().Add(time.Minute))) {
		return fmt.Errorf("recent authentication required")
	}
	if e.cfg.PostureURL == "" {
		return nil
	}
	if id.Subject == "" || id.DeviceID == "" {
		return fmt.Errorf("verified device identity required")
	}
	keyBytes, _ := json.Marshal([]string{id.Issuer, id.Subject, id.DeviceID})
	key := string(keyBytes)
	e.mu.Lock()
	cached, ok := e.cache[key]
	e.mu.Unlock()
	if ok && cached.ExpiresAt.After(time.Now()) {
		if cached.Compliant {
			return nil
		}
		return fmt.Errorf("device not compliant")
	}
	body, _ := json.Marshal(id)
	req, err := http.NewRequestWithContext(ctx, "POST", e.cfg.PostureURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if e.cfg.PostureTokenEnv != "" {
		secret := os.Getenv(e.cfg.PostureTokenEnv)
		if secret == "" {
			return fmt.Errorf("posture credential unavailable")
		}
		req.Header.Set("Authorization", "Bearer "+secret)
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return fmt.Errorf("posture service unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("posture service rejected request")
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 16385))
	if err != nil || len(data) > 16384 {
		return fmt.Errorf("invalid posture response")
	}
	var p posture
	if json.Unmarshal(data, &p) != nil || !p.ExpiresAt.After(time.Now()) {
		return fmt.Errorf("expired or invalid posture verdict")
	}
	if p.ExpiresAt.After(time.Now().Add(time.Minute)) {
		p.ExpiresAt = time.Now().Add(time.Minute)
	}
	e.mu.Lock()
	if len(e.cache) >= 10000 {
		clear(e.cache)
	}
	e.cache[key] = p
	e.mu.Unlock()
	if !p.Compliant {
		return fmt.Errorf("device not compliant")
	}
	return nil
}
