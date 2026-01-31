package threat

import (
	"bufio"
	"context"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"ads-httpproxy/internal/dnscache"
	"ads-httpproxy/internal/threat/builder"
	"ads-httpproxy/pkg/logging"

	"go.uber.org/zap"
)

// Manager handles IP blocking based on threat intelligence
type Manager struct {
	blockedNets    []*net.IPNet
	blockedIPs     map[string]struct{}
	blockedDomains map[string]struct{}
	dnsClient      *dnscache.Client
	mu             sync.RWMutex
	stopChan       chan struct{}
}

// NewManager creates a new threat manager
func NewManager() *Manager {
	return &Manager{
		blockedIPs:     make(map[string]struct{}),
		blockedDomains: make(map[string]struct{}),
		stopChan:       make(chan struct{}),
	}
}

// SetDNSClient sets the gRPC client for threat lookups
func (m *Manager) SetDNSClient(client *dnscache.Client) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.dnsClient = client
}

// LoadFromFile loads a list of CIDRs or IPs from a file
func (m *Manager) LoadFromFile(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	var newNets []*net.IPNet
	newIPs := make(map[string]struct{})

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Try CIDR
		_, network, err := net.ParseCIDR(line)
		if err == nil {
			newNets = append(newNets, network)
			continue
		}

		// Try IP
		ip := net.ParseIP(line)
		if ip != nil {
			newIPs[ip.String()] = struct{}{}
			continue
		}

		logging.Logger.Warn("Invalid IP/CIDR in threat list", zap.String("line", line))
	}

	m.mu.Lock()
	m.blockedNets = newNets
	m.blockedIPs = newIPs
	m.mu.Unlock()

	logging.Logger.Info("Loaded threat list",
		zap.Int("cidrs", len(newNets)),
		zap.Int("single_ips", len(newIPs)))

	return scanner.Err()
}

// IsBlocked checks if an IP is in the blocklist
func (m *Manager) IsBlocked(ipStr string) bool {
	// Clean IP (remove port if present)
	host, _, err := net.SplitHostPort(ipStr)
	if err == nil {
		ipStr = host
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	// Check exact match
	if _, ok := m.blockedIPs[ip.String()]; ok {
		return true
	}

	// Check generic match
	for _, network := range m.blockedNets {
		if network.Contains(ip) {
			return true
		}
	}

	return false
}

// StartAutoReload monitors the file for changes (mock implementation for now)
func (m *Manager) StartAutoReload(path string, interval time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		for range ticker.C {
			if err := m.LoadFromFile(path); err != nil {
				logging.Logger.Error("Failed to reload threat list", zap.Error(err))
			}
		}
	}()
}

// LoadThreatFeeds uses the native ListBuilder to fetch and aggregate multiple sources
func (m *Manager) LoadThreatFeeds(urls []string) error {
	b := builder.NewListBuilder()
	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	list, err := b.BuildFromFeeds(ctx, urls)
	if err != nil {
		return err
	}

	// Resource Limit Check
	const MaxNets = 100000
	const MaxIPs = 500000

	if len(list.Nets) > MaxNets {
		logging.Logger.Warn("Threat feed exceeded network limit, truncating", zap.Int("count", len(list.Nets)))
		list.Nets = list.Nets[:MaxNets]
	}
	if len(list.IPs) > MaxIPs {
		logging.Logger.Warn("Threat feed exceeded IP limit", zap.Int("count", len(list.IPs)))
	}

	m.mu.Lock()
	m.blockedNets = list.Nets
	m.blockedIPs = list.IPs
	m.blockedDomains = list.Domains
	m.mu.Unlock()

	return nil
}

// LoadFromURL fetches a threat list from a single URL (Legacy wrapper)
func (m *Manager) LoadFromURL(url string) error {
	return m.LoadThreatFeeds([]string{url})
}

// StartSync starts a background ticker to fetch and update lists from multiple URLs
func (m *Manager) StartSync(feedURLs []string, interval time.Duration) {
	if len(feedURLs) == 0 {
		return
	}
	// Initial Load
	if err := m.LoadThreatFeeds(feedURLs); err != nil {
		logging.Logger.Error("Failed initial threat sync", zap.Error(err))
	}

	ticker := time.NewTicker(interval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-m.stopChan:
				return
			case <-ticker.C:
				if err := m.LoadThreatFeeds(feedURLs); err != nil {
					logging.Logger.Error("Failed threat sync", zap.Error(err))
				} else {
					logging.Logger.Info("Synced threat feeds", zap.Int("sources", len(feedURLs)))
				}
			}
		}
	}()
}

// StopSync stops the background sync routine
func (m *Manager) StopSync() {
	close(m.stopChan)
}

// StartStreaming subscribes to threat updates
func (m *Manager) StartStreaming(ctx context.Context) {
	if m.dnsClient == nil {
		return
	}

	ch, err := m.dnsClient.Watch(ctx)
	if err != nil {
		logging.Logger.Error("Failed to start threat streaming", zap.Error(err))
		return
	}

	logging.Logger.Info("Subscribed to Threat Stream")

	go func() {
		for event := range ch {
			if event.Entry != nil && event.Entry.ThreatScore > 80 {
				m.mu.Lock()
				m.blockedDomains[event.Entry.Name] = struct{}{}
				m.mu.Unlock()
				logging.Logger.Warn("Received Threat Update: Blocking Domain",
					zap.String("domain", event.Entry.Name),
					zap.Int32("score", event.Entry.ThreatScore))
			}
		}
	}()
}

// CheckDomainViaCache checks a domain against the remote DNS Science cache
func (m *Manager) CheckDomainViaCache(ctx context.Context, domain string) (bool, int, error) {
	m.mu.RLock()
	// Check local cache first
	if _, ok := m.blockedDomains[domain]; ok {
		m.mu.RUnlock()
		return true, 100, nil // Locally blocked, assume max score or cached score if we stored it
	}
	client := m.dnsClient
	m.mu.RUnlock()

	if client == nil {
		return false, 0, nil
	}

	entry, err := client.CheckThreat(ctx, domain)
	if err != nil {
		// Fail open on error, but log it
		logging.Logger.Warn("Failed to check threat cache", zap.String("domain", domain), zap.Error(err))
		return false, 0, err
	}

	if entry == nil {
		return false, 0, nil
	}

	// Threat Logic: Block if Score > 80
	if entry.ThreatScore > 80 {
		return true, int(entry.ThreatScore), nil
	}

	return false, int(entry.ThreatScore), nil
}
