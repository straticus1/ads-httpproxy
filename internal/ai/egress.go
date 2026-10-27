package ai

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"time"
)

type EgressConfig struct {
	Enabled           bool              `json:"enabled" yaml:"enabled"`
	Hosts             []string          `json:"hosts" yaml:"hosts"`
	AllowedHosts      []string          `json:"allowed_hosts" yaml:"allowed_hosts"`
	AllowedModels     []string          `json:"allowed_models" yaml:"allowed_models"`
	RequestsPerMinute int               `json:"requests_per_minute" yaml:"requests_per_minute"`
	MaxBodyBytes      int64             `json:"max_body_bytes" yaml:"max_body_bytes"`
	CredentialEnv     map[string]string `json:"credential_env" yaml:"credential_env"`
}
type budget struct {
	window int64
	count  int
}
type Gate struct {
	cfg     EgressConfig
	mu      sync.Mutex
	budgets map[string]budget
}

func ValidateEgress(c EgressConfig) error {
	if c.RequestsPerMinute < 0 || c.RequestsPerMinute > 1000000 || c.MaxBodyBytes < 0 || c.MaxBodyBytes > 4<<20 {
		return fmt.Errorf("invalid AI egress budget/body limit")
	}
	if c.Enabled && len(c.Hosts) == 0 {
		return fmt.Errorf("AI egress requires explicit hosts")
	}
	for _, h := range append(append([]string{}, c.Hosts...), c.AllowedHosts...) {
		if h == "" || h != strings.ToLower(h) || strings.ContainsAny(h, "/ \\?#\r\n") {
			return fmt.Errorf("AI hosts must be lowercase exact authorities")
		}
	}
	for _, h := range c.AllowedHosts {
		if !slices.Contains(c.Hosts, h) {
			return fmt.Errorf("allowed AI host must be listed in hosts")
		}
	}
	for h, env := range c.CredentialEnv {
		if !slices.Contains(c.AllowedHosts, h) || env == "" {
			return fmt.Errorf("AI credentials require an allowed host and environment variable")
		}
	}
	return nil
}
func authority(raw string) string {
	u, err := url.Parse("https://" + raw)
	if err != nil {
		return ""
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if port := u.Port(); port != "" && port != "443" {
		return net.JoinHostPort(host, port)
	}
	return host
}
func NewGate(c EgressConfig) (*Gate, error) {
	if err := ValidateEgress(c); err != nil {
		return nil, err
	}
	c.Hosts = append([]string{}, c.Hosts...)
	c.AllowedHosts = append([]string{}, c.AllowedHosts...)
	c.AllowedModels = append([]string{}, c.AllowedModels...)
	for i, h := range c.Hosts {
		c.Hosts[i] = authority(h)
	}
	for i, h := range c.AllowedHosts {
		c.AllowedHosts[i] = authority(h)
	}
	credentials := make(map[string]string)
	for h, v := range c.CredentialEnv {
		credentials[authority(h)] = v
	}
	c.CredentialEnv = credentials
	if c.MaxBodyBytes == 0 {
		c.MaxBodyBytes = 1 << 20
	}
	if c.RequestsPerMinute == 0 {
		c.RequestsPerMinute = 60
	}
	return &Gate{cfg: c, budgets: make(map[string]budget)}, nil
}
func (g *Gate) Check(req *http.Request, tenant string) error {
	if g == nil || !g.cfg.Enabled || !slices.Contains(g.cfg.Hosts, authority(req.URL.Host)) {
		return nil
	}
	host := authority(req.URL.Host)
	if req.URL.User != nil {
		return fmt.Errorf("AI URL credentials are forbidden")
	}
	if !slices.Contains(g.cfg.AllowedHosts, host) {
		return fmt.Errorf("AI destination not approved")
	}
	// A credential must never be injected into an unencrypted connection.
	if req.URL.Scheme != "https" {
		return fmt.Errorf("AI destinations require HTTPS")
	}
	if req.Body != nil && req.Body != http.NoBody {
		original := req.Body
		data, err := io.ReadAll(io.LimitReader(original, g.cfg.MaxBodyBytes+1))
		original.Close()
		if err != nil || int64(len(data)) > g.cfg.MaxBodyBytes {
			return fmt.Errorf("AI request body unreadable or too large")
		}
		req.Body = io.NopCloser(bytes.NewReader(data))
		req.ContentLength = int64(len(data))
		req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(data)), nil }
		if len(g.cfg.AllowedModels) > 0 {
			var body struct {
				Model string `json:"model"`
			}
			if json.Unmarshal(data, &body) != nil || !slices.Contains(g.cfg.AllowedModels, body.Model) {
				return fmt.Errorf("AI model not approved or request is not supported JSON")
			}
		}
	} else if req.Method != "GET" && len(g.cfg.AllowedModels) > 0 {
		return fmt.Errorf("AI model required")
	}
	g.mu.Lock()
	now := time.Now().Unix() / 60
	if len(g.budgets) >= 10000 {
		for key, b := range g.budgets {
			if b.window != now {
				delete(g.budgets, key)
			}
		}
	}
	b, exists := g.budgets[tenant]
	if !exists && len(g.budgets) >= 10000 {
		g.mu.Unlock()
		return fmt.Errorf("AI budget capacity reached")
	}
	if b.window != now {
		b = budget{window: now}
	}
	if b.count >= g.cfg.RequestsPerMinute {
		g.mu.Unlock()
		return fmt.Errorf("AI request budget exceeded")
	}
	b.count++
	g.budgets[tenant] = b
	g.mu.Unlock()
	for _, h := range []string{"Authorization", "Proxy-Authorization", "Cookie", "X-API-Key", "Api-Key"} {
		req.Header.Del(h)
	}
	if name := g.cfg.CredentialEnv[host]; name != "" {
		secret := os.Getenv(name)
		if secret == "" {
			return fmt.Errorf("AI upstream credential unavailable")
		}
		req.Header.Set("Authorization", "Bearer "+secret)
	}
	return nil
}
