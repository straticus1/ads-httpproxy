package proxy

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"ads-httpproxy/internal/config"

	"golang.org/x/net/proxy"
)

// UpstreamManager handles dynamic upstream selection (Groups) and Dialing (Chains)
type UpstreamManager struct {
	groups map[string]*GroupState
	chains map[string]*ChainState
	mu     sync.RWMutex
	cancel context.CancelFunc
}

type GroupState struct {
	Config *config.UpstreamGroup
	// RR counter
	counter uint64
	// Health status (map[string]bool)
	health atomic.Value
}

type ChainState struct {
	Config *config.ProxyChain
}

func NewUpstreamManager(cfg *config.Config) *UpstreamManager {
	ctx, cancel := context.WithCancel(context.Background())
	um := &UpstreamManager{
		groups: make(map[string]*GroupState),
		chains: make(map[string]*ChainState),
		cancel: cancel,
	}

	for name, g := range cfg.UpstreamGroups {
		um.groups[name] = &GroupState{
			Config: g,
		}
		um.groups[name].health.Store(make(map[string]bool)) // Init health map
		go um.monitorHealth(ctx, um.groups[name])
	}

	for name, c := range cfg.Chains {
		um.chains[name] = &ChainState{
			Config: c,
		}
	}

	return um
}

// GetTarget resolves a target from a potentially grouped upstream name.
// If 'name' is a group, returns a healthy member.
// If 'name' is specific URL, returns it directly.
func (um *UpstreamManager) GetTarget(name string) (*url.URL, error) {
	um.mu.RLock()
	group, exists := um.groups[name]
	um.mu.RUnlock()

	if !exists {
		// Not a group, treat as direct URL
		return url.Parse(name)
	}

	// Group Logic
	targets := group.Config.Targets
	if len(targets) == 0 {
		return nil, fmt.Errorf("empty upstream group: %s", name)
	}

	// Try to find a healthy target with Round Robin
	// Loop through targets starting from current counter
	startIdx := atomic.AddUint64(&group.counter, 1)

	for i := 0; i < len(targets); i++ {
		idx := (startIdx + uint64(i)) % uint64(len(targets))
		targetStr := targets[idx]

		// Check health
		if val := group.health.Load(); val != nil {
			if healthMap, ok := val.(map[string]bool); ok {
				if healthy, exists := healthMap[targetStr]; exists && !healthy {
					continue // Skip unhealthy
				}
			}
		}

		return url.Parse(targetStr)
	}

	// All failed? Fail open or error?
	// For now, return the primary as fallback or error
	return url.Parse(targets[0])
}

// GetDialer returns a dialer context function.
// If 'chainName' is provided, it builds a proxy dialer chain.
// Otherwise it returns direct net.Dialer.
func (um *UpstreamManager) GetDialer(chainName string) (func(context.Context, string, string) (net.Conn, error), error) {
	if chainName == "" {
		d := &net.Dialer{Timeout: 30 * time.Second}
		return d.DialContext, nil
	}

	um.mu.RLock()
	chain, exists := um.chains[chainName]
	um.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("proxy chain not found: %s", chainName)
	}

	// Build the chain dialer
	var dialer proxy.Dialer = proxy.Direct
	var err error

	for _, proxyURL := range chain.Config.Proxies {
		u, errParse := url.Parse(proxyURL)
		if errParse != nil {
			return nil, fmt.Errorf("invalid proxy in chain %s: %v", proxyURL, errParse)
		}

		dialer, err = proxy.FromURL(u, dialer)
		if err != nil {
			return nil, fmt.Errorf("failed to create dialer for %s: %v", proxyURL, err)
		}
	}

	// Wrap proxy.Dialer (which doesn't always support Context depending on library version,
	// but golang.org/x/net/proxy typically has Dial)
	// We'll use a wrapper to support Context if possible, or fallback to background.

	if contextDialer, ok := dialer.(proxy.ContextDialer); ok {
		return contextDialer.DialContext, nil
	}

	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		// Respect timeout from context if possible
		return dialer.Dial(network, addr)
	}, nil
}

// Transport returns an http.Transport configured for the given Chain.
func (um *UpstreamManager) Transport(chainName string) (*http.Transport, error) {
	dialFunc, err := um.GetDialer(chainName)
	if err != nil {
		return nil, err
	}

	return &http.Transport{
		DialContext:     dialFunc,
		MaxIdleConns:    100,
		IdleConnTimeout: 90 * time.Second,
	}, nil
}

// Shutdown stops all background health checks
func (um *UpstreamManager) Shutdown() {
	if um.cancel != nil {
		um.cancel()
	}
}

// monitorHealth actively checks the health of upstream targets
func (um *UpstreamManager) monitorHealth(ctx context.Context, group *GroupState) {
	if group.Config.HealthCheck == "" {
		return // No checks configured
	}

	client := &http.Client{Timeout: 2 * time.Second}
	ticker := time.NewTicker(10 * time.Second) // configurable?
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// New map for atomic swap
			newHealth := make(map[string]bool)

			for _, target := range group.Config.Targets {
				// Construct Health URL
				checkURL := target + group.Config.HealthCheck
				if u, err := url.Parse(target); err == nil {
					rel, _ := url.Parse(group.Config.HealthCheck)
					checkURL = u.ResolveReference(rel).String()
				}

				resp, err := client.Get(checkURL)
				healthy := false
				if err == nil {
					if resp.StatusCode >= 200 && resp.StatusCode < 300 {
						healthy = true
					}
					resp.Body.Close()
				}
				newHealth[target] = healthy
			}
			// Atomic store
			group.health.Store(newHealth)
		}
	}
}
