package reputation

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"ads-httpproxy/pkg/logging"

	"go.uber.org/zap"
)

// URLEntry represents a malicious or categorized URL
type URLEntry struct {
	URL          string
	Category     string   // malware, phishing, adult, gambling, etc.
	ThreatScore  int      // 0-100
	Sources      []string // Which feeds reported it
	Tags         []string
	FirstSeen    time.Time
	LastSeen     time.Time
	Hash         string // SHA256 of normalized URL
}

// FeedManager aggregates multiple URL reputation feeds
type FeedManager struct {
	mu         sync.RWMutex
	entries    map[string]*URLEntry // URL -> Entry
	hashIndex  map[string]*URLEntry // SHA256 -> Entry
	Sources    []FeedSource         // Exported for configuration
	httpClient *http.Client
	stopChan   chan struct{}
}

// FeedSource defines a threat intelligence feed
type FeedSource struct {
	Name        string
	URL         string
	Type        string // plaintext, csv, json, abuse_ch
	Category    string // malware, phishing, adult, gambling, etc.
	UpdateFreq  time.Duration
	Enabled     bool
	Parser      FeedParser
}

// FeedParser interface for different feed formats
type FeedParser interface {
	Parse(reader io.Reader) ([]*URLEntry, error)
}

// NewFeedManager creates a new URL feed manager
func NewFeedManager() *FeedManager {
	return &FeedManager{
		entries:   make(map[string]*URLEntry),
		hashIndex: make(map[string]*URLEntry),
		stopChan:  make(chan struct{}),
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:       10,
				IdleConnTimeout:    90 * time.Second,
				DisableCompression: false,
			},
		},
	}
}

// InitDefaultFeeds configures well-known public threat feeds
func (fm *FeedManager) InitDefaultFeeds() {
	fm.Sources = []FeedSource{
		// URLhaus - Malware distribution sites (abuse.ch)
		{
			Name:       "URLhaus",
			URL:        "https://urlhaus.abuse.ch/downloads/csv_recent/",
			Type:       "csv",
			Category:   "malware",
			UpdateFreq: 5 * time.Minute,
			Enabled:    true,
			Parser:     &URLhausParser{},
		},
		// PhishTank - Phishing URLs
		{
			Name:       "PhishTank",
			URL:        "http://data.phishtank.com/data/online-valid.csv",
			Type:       "csv",
			Category:   "phishing",
			UpdateFreq: 1 * time.Hour,
			Enabled:    true,
			Parser:     &PhishTankParser{},
		},
		// OpenPhish - Community phishing feed
		{
			Name:       "OpenPhish",
			URL:        "https://openphish.com/feed.txt",
			Type:       "plaintext",
			Category:   "phishing",
			UpdateFreq: 1 * time.Hour,
			Enabled:    true,
			Parser:     &PlaintextParser{Category: "phishing", Score: 90},
		},
		// Abuse.ch ThreatFox (malware IOCs)
		{
			Name:       "ThreatFox",
			URL:        "https://threatfox.abuse.ch/export/csv/recent/",
			Type:       "csv",
			Category:   "malware",
			UpdateFreq: 5 * time.Minute,
			Enabled:    true,
			Parser:     &ThreatFoxParser{},
		},
		// Emerging Threats - Compromised sites
		{
			Name:       "EmergingThreats",
			URL:        "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
			Type:       "plaintext",
			Category:   "malware",
			UpdateFreq: 1 * time.Hour,
			Enabled:    false, // IP-based, not URL-based
			Parser:     &PlaintextParser{Category: "malware", Score: 85},
		},
		// Custom DNS Science feed (if available)
		{
			Name:       "DNSScience",
			URL:        "https://feed.dnsscience.com/v1/threats",
			Type:       "json",
			Category:   "mixed",
			UpdateFreq: 15 * time.Minute,
			Enabled:    false, // Enable via config
			Parser:     &JSONParser{},
		},
	}

	logging.Logger.Info("Initialized URL reputation feeds",
		zap.Int("total", len(fm.Sources)),
		zap.Int("enabled", fm.countEnabled()))
}

// AddCustomFeed adds a user-defined feed
func (fm *FeedManager) AddCustomFeed(source FeedSource) {
	fm.mu.Lock()
	defer fm.mu.Unlock()
	fm.Sources = append(fm.Sources, source)
	logging.Logger.Info("Added custom feed", zap.String("name", source.Name))
}

// StartSync begins automatic feed updates
func (fm *FeedManager) StartSync(ctx context.Context) {
	// Initial load
	fm.syncAll(ctx)

	// Start periodic updates
	for _, source := range fm.Sources {
		if !source.Enabled {
			continue
		}

		go fm.syncLoop(ctx, source)
	}
}

// syncLoop periodically fetches a single feed
func (fm *FeedManager) syncLoop(ctx context.Context, source FeedSource) {
	ticker := time.NewTicker(source.UpdateFreq)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-fm.stopChan:
			return
		case <-ticker.C:
			if err := fm.fetchFeed(ctx, source); err != nil {
				logging.Logger.Error("Failed to sync feed",
					zap.String("feed", source.Name),
					zap.Error(err))
			}
		}
	}
}

// syncAll fetches all enabled feeds once
func (fm *FeedManager) syncAll(ctx context.Context) {
	var wg sync.WaitGroup

	for _, source := range fm.Sources {
		if !source.Enabled {
			continue
		}

		wg.Add(1)
		go func(src FeedSource) {
			defer wg.Done()
			if err := fm.fetchFeed(ctx, src); err != nil {
				logging.Logger.Error("Failed to fetch feed",
					zap.String("feed", src.Name),
					zap.Error(err))
			}
		}(source)
	}

	wg.Wait()
	fm.logStats()
}

// fetchFeed downloads and parses a single feed
func (fm *FeedManager) fetchFeed(ctx context.Context, source FeedSource) error {
	req, err := http.NewRequestWithContext(ctx, "GET", source.URL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "ads-httpproxy/1.0")

	resp, err := fm.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("feed returned status %d", resp.StatusCode)
	}

	// Parse feed
	entries, err := source.Parser.Parse(resp.Body)
	if err != nil {
		return err
	}

	// Merge into database
	fm.merge(entries, source.Name)

	logging.Logger.Info("Synced feed",
		zap.String("feed", source.Name),
		zap.Int("entries", len(entries)))

	return nil
}

// merge adds entries to the database
func (fm *FeedManager) merge(entries []*URLEntry, sourceName string) {
	fm.mu.Lock()
	defer fm.mu.Unlock()

	now := time.Now()
	newCount := 0

	for _, entry := range entries {
		// Normalize URL
		normalized := normalizeURL(entry.URL)
		if normalized == "" {
			continue
		}

		entry.URL = normalized
		entry.Hash = hashURL(normalized)

		// Check if exists
		if existing, ok := fm.entries[normalized]; ok {
			// Update existing
			existing.LastSeen = now
			if !contains(existing.Sources, sourceName) {
				existing.Sources = append(existing.Sources, sourceName)
			}
			// Increase score if multiple sources report it
			if len(existing.Sources) > 1 {
				existing.ThreatScore = min(100, existing.ThreatScore+10)
			}
		} else {
			// New entry
			entry.FirstSeen = now
			entry.LastSeen = now
			entry.Sources = []string{sourceName}
			fm.entries[normalized] = entry
			fm.hashIndex[entry.Hash] = entry
			newCount++
		}
	}

	logging.Logger.Debug("Merged feed entries",
		zap.String("source", sourceName),
		zap.Int("new", newCount),
		zap.Int("total", len(fm.entries)))
}

// Check looks up a URL in the reputation database
func (fm *FeedManager) Check(urlStr string) (*URLEntry, bool) {
	normalized := normalizeURL(urlStr)
	if normalized == "" {
		return nil, false
	}

	fm.mu.RLock()
	defer fm.mu.RUnlock()

	// Direct lookup
	if entry, ok := fm.entries[normalized]; ok {
		return entry, true
	}

	// Hash lookup (for privacy)
	hash := hashURL(normalized)
	if entry, ok := fm.hashIndex[hash]; ok {
		return entry, true
	}

	return nil, false
}

// GetStats returns current database statistics
func (fm *FeedManager) GetStats() map[string]interface{} {
	fm.mu.RLock()
	defer fm.mu.RUnlock()

	categories := make(map[string]int)
	sources := make(map[string]int)

	for _, entry := range fm.entries {
		categories[entry.Category]++
		for _, src := range entry.Sources {
			sources[src]++
		}
	}

	return map[string]interface{}{
		"total_urls":  len(fm.entries),
		"categories":  categories,
		"sources":     sources,
		"feeds":       len(fm.Sources),
	}
}

// Cleanup removes old entries
func (fm *FeedManager) Cleanup(maxAge time.Duration) {
	fm.mu.Lock()
	defer fm.mu.Unlock()

	cutoff := time.Now().Add(-maxAge)
	removed := 0

	for url, entry := range fm.entries {
		if entry.LastSeen.Before(cutoff) {
			delete(fm.entries, url)
			delete(fm.hashIndex, entry.Hash)
			removed++
		}
	}

	logging.Logger.Info("Cleaned up old reputation entries",
		zap.Int("removed", removed),
		zap.Int("remaining", len(fm.entries)))
}

// Stop gracefully stops the feed manager
func (fm *FeedManager) Stop() {
	close(fm.stopChan)
}

// Helper functions

func normalizeURL(rawURL string) string {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return ""
	}

	// Parse URL
	u, err := url.Parse(rawURL)
	if err != nil {
		// Try adding scheme
		u, err = url.Parse("http://" + rawURL)
		if err != nil {
			return ""
		}
	}

	// Normalize: lowercase host, remove fragment, sort query params
	u.Host = strings.ToLower(u.Host)
	u.Fragment = ""

	return u.String()
}

func hashURL(urlStr string) string {
	h := sha256.Sum256([]byte(urlStr))
	return fmt.Sprintf("%x", h)
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (fm *FeedManager) countEnabled() int {
	count := 0
	for _, src := range fm.Sources {
		if src.Enabled {
			count++
		}
	}
	return count
}

func (fm *FeedManager) logStats() {
	stats := fm.GetStats()
	logging.Logger.Info("URL Reputation Database Statistics",
		zap.Any("stats", stats))
}

// Feed Parsers

// PlaintextParser - One URL per line
type PlaintextParser struct {
	Category string
	Score    int
}

func (p *PlaintextParser) Parse(reader io.Reader) ([]*URLEntry, error) {
	var entries []*URLEntry
	scanner := bufio.NewScanner(reader)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		entries = append(entries, &URLEntry{
			URL:         line,
			Category:    p.Category,
			ThreatScore: p.Score,
		})
	}

	return entries, scanner.Err()
}

// URLhausParser - abuse.ch URLhaus CSV format
type URLhausParser struct{}

func (p *URLhausParser) Parse(reader io.Reader) ([]*URLEntry, error) {
	var entries []*URLEntry
	csvReader := csv.NewReader(reader)
	csvReader.Comment = '#'

	for {
		record, err := csvReader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}

		// URLhaus CSV: id,dateadded,url,url_status,threat,tags,urlhaus_link,reporter
		if len(record) < 5 {
			continue
		}

		urlStr := record[2]
		threat := record[4]
		tags := []string{}
		if len(record) > 5 && record[5] != "" {
			tags = strings.Split(record[5], ",")
		}

		entries = append(entries, &URLEntry{
			URL:         urlStr,
			Category:    "malware",
			ThreatScore: 95,
			Tags:        tags,
		})

		_ = threat // Could use for subcategory
	}

	return entries, nil
}

// PhishTankParser - PhishTank CSV format
type PhishTankParser struct{}

func (p *PhishTankParser) Parse(reader io.Reader) ([]*URLEntry, error) {
	var entries []*URLEntry
	csvReader := csv.NewReader(reader)

	// Skip header
	csvReader.Read()

	for {
		record, err := csvReader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}

		// PhishTank CSV: phish_id,url,phish_detail_url,submission_time,verified,verification_time,online,target
		if len(record) < 2 {
			continue
		}

		entries = append(entries, &URLEntry{
			URL:         record[1],
			Category:    "phishing",
			ThreatScore: 90,
		})
	}

	return entries, nil
}

// ThreatFoxParser - abuse.ch ThreatFox CSV format
type ThreatFoxParser struct{}

func (p *ThreatFoxParser) Parse(reader io.Reader) ([]*URLEntry, error) {
	var entries []*URLEntry
	csvReader := csv.NewReader(reader)
	csvReader.Comment = '#'

	for {
		record, err := csvReader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}

		// ThreatFox CSV: first_seen,ioc_type,ioc_value,threat_type,malware,...
		if len(record) < 5 {
			continue
		}

		iocType := record[1]
		iocValue := record[2]
		threatType := record[3]

		// Only process URL IOCs
		if iocType != "url" {
			continue
		}

		entries = append(entries, &URLEntry{
			URL:         iocValue,
			Category:    "malware",
			ThreatScore: 95,
			Tags:        []string{threatType},
		})
	}

	return entries, nil
}

// JSONParser - Generic JSON feed parser
type JSONParser struct{}

func (p *JSONParser) Parse(reader io.Reader) ([]*URLEntry, error) {
	var rawData interface{}
	if err := json.NewDecoder(reader).Decode(&rawData); err != nil {
		return nil, err
	}

	// This would need to be customized per JSON feed format
	// For now, just a placeholder
	return []*URLEntry{}, nil
}
