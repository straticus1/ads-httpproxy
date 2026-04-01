package accounting

import (
	"strings"
	"sync"
)

// Classifier categorizes URLs into traffic categories
type Classifier struct {
	mu      sync.RWMutex
	domains map[string]string     // domain -> category
	patterns map[string][]string  // category -> domain patterns
}

// NewClassifier creates a new URL classifier
func NewClassifier() *Classifier {
	c := &Classifier{
		domains:  make(map[string]string),
		patterns: make(map[string][]string),
	}

	// Load default categories
	c.loadDefaultCategories()

	return c
}

// loadDefaultCategories initializes common categorizations
func (c *Classifier) loadDefaultCategories() {
	// Social Media
	c.AddDomains("social_media", []string{
		"facebook.com", "*.facebook.com",
		"twitter.com", "*.twitter.com", "x.com", "*.x.com",
		"instagram.com", "*.instagram.com",
		"linkedin.com", "*.linkedin.com",
		"tiktok.com", "*.tiktok.com",
		"snapchat.com", "*.snapchat.com",
		"reddit.com", "*.reddit.com",
		"pinterest.com", "*.pinterest.com",
	})

	// Video Streaming
	c.AddDomains("video_streaming", []string{
		"youtube.com", "*.youtube.com", "youtu.be",
		"netflix.com", "*.netflix.com",
		"hulu.com", "*.hulu.com",
		"disney.com", "*.disney.com", "disneyplus.com",
		"hbo.com", "*.hbo.com", "hbomax.com",
		"twitch.tv", "*.twitch.tv",
		"vimeo.com", "*.vimeo.com",
		"dailymotion.com", "*.dailymotion.com",
	})

	// Shopping
	c.AddDomains("shopping", []string{
		"amazon.com", "*.amazon.com",
		"ebay.com", "*.ebay.com",
		"etsy.com", "*.etsy.com",
		"walmart.com", "*.walmart.com",
		"target.com", "*.target.com",
		"aliexpress.com", "*.aliexpress.com",
		"shopify.com", "*.shopify.com",
	})

	// News & Media
	c.AddDomains("news", []string{
		"cnn.com", "*.cnn.com",
		"bbc.com", "bbc.co.uk", "*.bbc.com",
		"nytimes.com", "*.nytimes.com",
		"wsj.com", "*.wsj.com",
		"reuters.com", "*.reuters.com",
		"bloomberg.com", "*.bloomberg.com",
		"theguardian.com", "*.theguardian.com",
	})

	// Finance & Banking
	c.AddDomains("banking", []string{
		"paypal.com", "*.paypal.com",
		"chase.com", "*.chase.com",
		"bankofamerica.com", "*.bankofamerica.com",
		"wellsfargo.com", "*.wellsfargo.com",
		"citibank.com", "*.citibank.com",
		"venmo.com", "*.venmo.com",
		"coinbase.com", "*.coinbase.com",
		"blockchain.com", "*.blockchain.com",
	})

	// Cloud & Storage
	c.AddDomains("cloud_storage", []string{
		"drive.google.com", "docs.google.com",
		"dropbox.com", "*.dropbox.com",
		"onedrive.com", "*.onedrive.com",
		"box.com", "*.box.com",
		"icloud.com", "*.icloud.com",
		"mega.nz", "mega.io",
	})

	// Email
	c.AddDomains("email", []string{
		"gmail.com", "mail.google.com",
		"outlook.com", "outlook.office.com",
		"yahoo.com", "mail.yahoo.com",
		"protonmail.com", "*.protonmail.com",
	})

	// Work/Productivity
	c.AddDomains("productivity", []string{
		"slack.com", "*.slack.com",
		"teams.microsoft.com", "*.teams.microsoft.com",
		"zoom.us", "*.zoom.us",
		"webex.com", "*.webex.com",
		"notion.so", "*.notion.so",
		"asana.com", "*.asana.com",
		"trello.com", "*.trello.com",
		"jira.atlassian.com", "*.atlassian.net",
	})

	// Gaming
	c.AddDomains("gaming", []string{
		"steam.com", "*.steampowered.com",
		"epicgames.com", "*.epicgames.com",
		"xbox.com", "*.xbox.com",
		"playstation.com", "*.playstation.com",
		"nintendo.com", "*.nintendo.com",
		"roblox.com", "*.roblox.com",
		"minecraft.net", "*.minecraft.net",
	})

	// Adult Content (for filtering)
	c.AddDomains("adult", []string{
		"pornhub.com", "*.pornhub.com",
		"xvideos.com", "*.xvideos.com",
		"xnxx.com", "*.xnxx.com",
		// ... (truncated for brevity)
	})

	// Gambling
	c.AddDomains("gambling", []string{
		"bet365.com", "*.bet365.com",
		"draftkings.com", "*.draftkings.com",
		"fanduel.com", "*.fanduel.com",
		"caesars.com", "*.caesars.com",
	})

	// VPN/Proxy (for detection)
	c.AddDomains("vpn_proxy", []string{
		"nordvpn.com", "*.nordvpn.com",
		"expressvpn.com", "*.expressvpn.com",
		"protonvpn.com", "*.protonvpn.com",
		"tor.org", "*.torproject.org",
	})

	// File Sharing
	c.AddDomains("file_sharing", []string{
		"wetransfer.com", "*.wetransfer.com",
		"sendspace.com", "*.sendspace.com",
		"mediafire.com", "*.mediafire.com",
		"rapidshare.com", "*.rapidshare.com",
	})

	// Malware/Phishing (for blocking)
	c.AddDomains("malware", []string{
		// Populated from threat intelligence feeds
	})

	// Search Engines
	c.AddDomains("search", []string{
		"google.com", "*.google.com",
		"bing.com", "*.bing.com",
		"duckduckgo.com", "*.duckduckgo.com",
		"yahoo.com", "search.yahoo.com",
	})

	// CDN & Infrastructure
	c.AddDomains("cdn", []string{
		"cloudflare.com", "*.cloudflare.com",
		"akamai.com", "*.akamai.com",
		"fastly.com", "*.fastly.com",
		"cloudfront.net", "*.cloudfront.net",
	})

	// Development
	c.AddDomains("development", []string{
		"github.com", "*.github.com",
		"gitlab.com", "*.gitlab.com",
		"stackoverflow.com", "*.stackoverflow.com",
		"docker.com", "*.docker.com",
	})
}

// Classify categorizes a URL/domain
func (c *Classifier) Classify(host string) string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Direct domain match
	if category, ok := c.domains[host]; ok {
		return category
	}

	// Wildcard pattern match
	for category, patterns := range c.patterns {
		for _, pattern := range patterns {
			if matchWildcard(pattern, host) {
				return category
			}
		}
	}

	// Default category
	return "uncategorized"
}

// AddDomains adds domain mappings to a category
func (c *Classifier) AddDomains(category string, domains []string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, domain := range domains {
		if strings.HasPrefix(domain, "*.") {
			// Wildcard pattern
			c.patterns[category] = append(c.patterns[category], domain)
		} else {
			// Exact domain
			c.domains[domain] = category
		}
	}
}

// matchWildcard performs simple wildcard matching
func matchWildcard(pattern, str string) bool {
	if !strings.Contains(pattern, "*") {
		return pattern == str
	}

	// Handle *.example.com pattern
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[2:]
		return strings.HasSuffix(str, suffix) || str == suffix[1:]
	}

	// Handle example.* pattern
	if strings.HasSuffix(pattern, ".*") {
		prefix := pattern[:len(pattern)-2]
		return strings.HasPrefix(str, prefix)
	}

	return false
}

// GetCategories returns all known categories
func (c *Classifier) GetCategories() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	categories := make(map[string]bool)

	for _, category := range c.domains {
		categories[category] = true
	}

	for category := range c.patterns {
		categories[category] = true
	}

	result := make([]string, 0, len(categories))
	for category := range categories {
		result = append(result, category)
	}

	return result
}

// LoadFromFile loads category mappings from a file
func (c *Classifier) LoadFromFile(path string) error {
	// TODO: Implement loading from JSON/YAML file
	// Format:
	// {
	//   "social_media": ["facebook.com", "*.facebook.com"],
	//   "shopping": ["amazon.com", "*.amazon.com"]
	// }
	return nil
}

// UpdateFromThreatIntel updates malware category from threat intelligence
func (c *Classifier) UpdateFromThreatIntel(maliciousDomains []string) {
	c.AddDomains("malware", maliciousDomains)
}
