package builder

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"ads-httpproxy/pkg/logging"

	"go.uber.org/zap"
)

const MaxFeedSize = 50 * 1024 * 1024 // 50MB per feed limit

// ListBuilder handles fetching and aggregating threat lists efficiently in Go.
type ListBuilder struct {
	client *http.Client
}

func NewListBuilder() *ListBuilder {
	return &ListBuilder{
		client: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:       100,
				IdleConnTimeout:    90 * time.Second,
				DisableCompression: false, // Enable gzip for speed
			},
		},
	}
}

// BuiltList contains the aggregated data
type BuiltList struct {
	IPs     map[string]struct{}
	Nets    []*net.IPNet
	Domains map[string]struct{}
}

// BuildFromFeeds fetches multiple feeds in parallel and aggregates them.
// This replaces the Python script's functionality with native Go concurrency.
func (b *ListBuilder) BuildFromFeeds(ctx context.Context, urls []string) (*BuiltList, error) {
	var wg sync.WaitGroup
	result := &BuiltList{
		IPs:     make(map[string]struct{}),
		Domains: make(map[string]struct{}),
		Nets:    make([]*net.IPNet, 0),
	}
	var mu sync.Mutex

	for _, url := range urls {
		wg.Add(1)
		go func(u string) {
			defer wg.Done()
			b.processFeed(ctx, u, result, &mu)
		}(url)
	}

	wg.Wait()

	logging.Logger.Info("List Build Complete",
		zap.Int("ips", len(result.IPs)),
		zap.Int("nets", len(result.Nets)),
		zap.Int("domains", len(result.Domains)))

	return result, nil
}

func (b *ListBuilder) processFeed(ctx context.Context, url string, result *BuiltList, mu *sync.Mutex) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		logging.Logger.Error("Failed to create request", zap.String("url", url), zap.Error(err))
		return
	}
	req.Header.Set("User-Agent", "ads-httpproxy-builder/1.0")

	resp, err := b.client.Do(req)
	if err != nil {
		logging.Logger.Warn("Failed to fetch feed", zap.String("url", url), zap.Error(err))
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		logging.Logger.Warn("Feed returned bad status", zap.String("url", url), zap.Int("status", resp.StatusCode))
		return
	}

	// Temporary threaded storage to minimize lock contention?
	// For simplicity, just lock batch or line. Locking per line is slow.
	// Ideally parse whole file then merge.

	localIPs := make(map[string]struct{})
	localDomains := make(map[string]struct{})
	localNets := make([]*net.IPNet, 0)

	// Limit Reader to prevent OOM
	limitReader := io.LimitReader(resp.Body, MaxFeedSize)
	scanner := bufio.NewScanner(limitReader)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Try CIDR
		if _, network, err := net.ParseCIDR(line); err == nil {
			localNets = append(localNets, network)
			continue
		}

		// Try IP
		if ip := net.ParseIP(line); ip != nil {
			localIPs[ip.String()] = struct{}{}
			continue
		}

		// Assume Domain if not IP/CIDR (basic validation)
		if strings.Contains(line, ".") {
			localDomains[line] = struct{}{}
		}
	}

	if err := scanner.Err(); err != nil {
		logging.Logger.Warn("Error scanning feed", zap.String("url", url), zap.Error(err))
	}

	// Merge
	mu.Lock()
	defer mu.Unlock()

	for ip := range localIPs {
		result.IPs[ip] = struct{}{}
	}
	for domain := range localDomains {
		result.Domains[domain] = struct{}{}
	}
	result.Nets = append(result.Nets, localNets...)
}
