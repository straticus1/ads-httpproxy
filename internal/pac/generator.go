package pac

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"text/template"
)

// Policy defines blocking/routing policy for PAC generation
type Policy struct {
	// User/Tenant identification
	UserID     string
	TenantID   string
	Department string

	// Proxy settings
	ProxyAddr     string   // Proxy server address
	ProxyPort     int      // Proxy port
	BackupProxies []string // Fallback proxies

	// Bypass rules (don't use proxy)
	BypassDomains  []string // Domains to bypass
	BypassNetworks []string // CIDR networks to bypass
	DirectDomains  []string // Go direct, skip proxy

	// Content filtering (block via proxy)
	BlockAdult     bool
	BlockGambling  bool
	BlockSocial    bool
	BlockStreaming bool
	BlockPiracy    bool
	BlockCrypto    bool
	BlockAds       bool

	// Custom block lists
	BlockedDomains  []string
	BlockedKeywords []string

	// Allowed overrides (whitelist)
	AllowedDomains []string

	// Time-based restrictions
	BlockWorkHours bool // Block certain content during work hours
	WorkHoursStart int  // 9 = 9 AM
	WorkHoursEnd   int  // 17 = 5 PM

	// Geographic routing
	UseGeoRouting   bool
	RegionalProxies map[string]string // Country code -> proxy

	// Authentication
	RequireAuth bool
	AuthRealm   string
}

// Generator creates PAC files
type Generator struct {
	DefaultProxy string
	template     *template.Template
}

// NewGenerator creates a new PAC generator
func NewGenerator(defaultProxy string) *Generator {
	tmpl := template.Must(template.New("pac").Parse(pacTemplate))
	return &Generator{
		DefaultProxy: defaultProxy,
		template:     tmpl,
	}
}

// Generate creates a PAC file for the given policy
func (g *Generator) Generate(policy *Policy) (string, error) {
	if policy == nil {
		return "", fmt.Errorf("PAC policy is required")
	}
	copy := *policy
	policy = &copy
	policy.UserID = strings.NewReplacer("\r", "\\r", "\n", "\\n").Replace(policy.UserID)
	policy.TenantID = strings.NewReplacer("\r", "\\r", "\n", "\\n").Replace(policy.TenantID)
	policy.Department = strings.NewReplacer("\r", "\\r", "\n", "\\n").Replace(policy.Department)
	// Default proxy if not set
	if policy.ProxyAddr == "" {
		policy.ProxyAddr = g.DefaultProxy
	}
	if policy.ProxyPort == 0 {
		policy.ProxyPort = 8080
	}

	if policy.ProxyPort < 1 || policy.ProxyPort > 65535 {
		return "", fmt.Errorf("invalid PAC proxy port")
	}
	if policy.ProxyAddr == "" || strings.ContainsAny(policy.ProxyAddr, "; \r\n") {
		return "", fmt.Errorf("invalid PAC proxy host")
	}
	data := struct {
		Policy          *Policy
		NetworkList     string
		KeywordList     string
		ProxyLiteral    string
		ProxyString     string
		BackupString    string
		BypassList      string
		DirectList      string
		BlockedList     string
		AllowedList     string
		BlockCategories map[string]bool
	}{
		Policy:      policy,
		ProxyString: fmt.Sprintf("PROXY %s", net.JoinHostPort(policy.ProxyAddr, fmt.Sprint(policy.ProxyPort))),
		BlockCategories: map[string]bool{
			"adult":     policy.BlockAdult,
			"gambling":  policy.BlockGambling,
			"social":    policy.BlockSocial,
			"streaming": policy.BlockStreaming,
			"piracy":    policy.BlockPiracy,
			"crypto":    policy.BlockCrypto,
			"ads":       policy.BlockAds,
		},
	}

	// Build backup proxy string
	if len(policy.BackupProxies) > 0 {
		data.BackupString = "; " + strings.Join(policy.BackupProxies, "; ")
	}

	networks := make([]map[string]string, 0, len(policy.BypassNetworks))
	for _, cidr := range policy.BypassNetworks {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil || network.IP.To4() == nil {
			return "", fmt.Errorf("PAC bypass network requires an IPv4 CIDR: %s", cidr)
		}
		networks = append(networks, map[string]string{"network": network.IP.String(), "mask": net.IP(network.Mask).String()})
	}
	networkJSON, _ := json.Marshal(networks)
	data.NetworkList = string(networkJSON)
	data.KeywordList = g.buildDomainList(policy.BlockedKeywords)
	literal, _ := json.Marshal(data.ProxyString + data.BackupString)
	data.ProxyLiteral = string(literal)

	// Build bypass lists
	data.BypassList = g.buildDomainList(policy.BypassDomains)
	data.DirectList = g.buildDomainList(policy.DirectDomains)
	data.BlockedList = g.buildDomainList(policy.BlockedDomains)
	data.AllowedList = g.buildDomainList(policy.AllowedDomains)

	var buf bytes.Buffer
	if err := g.template.Execute(&buf, data); err != nil {
		return "", err
	}

	return buf.String(), nil
}

// GenerateForUser creates a PAC file for a specific user
func (g *Generator) GenerateForUser(userID string, tenantPolicy *Policy, userOverrides *Policy) (string, error) {
	// Merge tenant policy with user overrides
	policy := g.mergePolicies(tenantPolicy, userOverrides)
	policy.UserID = userID
	return g.Generate(policy)
}

// mergePolicies combines tenant and user policies
func (g *Generator) mergePolicies(tenant, user *Policy) *Policy {
	if tenant == nil {
		tenant = &Policy{}
	}
	result := *tenant // Copy tenant policy
	result.BypassDomains = append([]string(nil), tenant.BypassDomains...)
	result.DirectDomains = append([]string(nil), tenant.DirectDomains...)
	result.AllowedDomains = append([]string(nil), tenant.AllowedDomains...)
	result.BlockedDomains = append([]string(nil), tenant.BlockedDomains...)

	if user == nil {
		return &result
	}

	// User overrides
	if user.ProxyAddr != "" {
		result.ProxyAddr = user.ProxyAddr
	}
	if user.ProxyPort != 0 {
		result.ProxyPort = user.ProxyPort
	}

	// Merge lists
	result.BypassDomains = append(result.BypassDomains, user.BypassDomains...)
	result.DirectDomains = append(result.DirectDomains, user.DirectDomains...)
	result.AllowedDomains = append(result.AllowedDomains, user.AllowedDomains...)
	result.BlockedDomains = append(result.BlockedDomains, user.BlockedDomains...)

	// User can only make blocking MORE restrictive, not less
	result.BlockAdult = tenant.BlockAdult || user.BlockAdult
	result.BlockGambling = tenant.BlockGambling || user.BlockGambling
	result.BlockSocial = tenant.BlockSocial || user.BlockSocial
	result.BlockStreaming = tenant.BlockStreaming || user.BlockStreaming
	result.BlockPiracy = tenant.BlockPiracy || user.BlockPiracy
	result.BlockCrypto = tenant.BlockCrypto || user.BlockCrypto
	result.BlockAds = tenant.BlockAds || user.BlockAds

	return &result
}

// buildDomainList creates JavaScript array literal
func (g *Generator) buildDomainList(domains []string) string {
	if len(domains) == 0 {
		return "[]"
	}

	data, _ := json.Marshal(domains)
	return string(data)
}

// IsPrivateNetwork checks if an IP is in private address space
func IsPrivateNetwork(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"fc00::/7",
		"fe80::/10",
		"::1/128",
	}

	for _, cidr := range privateRanges {
		_, network, _ := net.ParseCIDR(cidr)
		if network != nil && network.Contains(ip) {
			return true
		}
	}

	return false
}

// PAC file template
const pacTemplate = `// Proxy Auto-Configuration (PAC) File
// Generated for: {{.Policy.UserID}}{{if .Policy.TenantID}} (Tenant: {{.Policy.TenantID}}){{end}}
// Policy: {{if .Policy.Department}}{{.Policy.Department}}{{else}}Default{{end}}

function domainMatches(host, domain) {
    domain = domain.toLowerCase().replace(/^\*\./, "").replace(/^\./, "");
    return host === domain || dnsDomainIs(host, "." + domain);
}

function FindProxyForURL(url, host) {
    // Normalize
    var lhost = host.toLowerCase();
    var lurl = url.toLowerCase();

    // ================================================================
    // ALWAYS BYPASS (Private networks, localhost)
    // ================================================================

    if (isPlainHostName(host) ||
        shExpMatch(host, "*.local") ||
        isInNet(dnsResolve(host), "10.0.0.0", "255.0.0.0") ||
        isInNet(dnsResolve(host), "172.16.0.0", "255.240.0.0") ||
        isInNet(dnsResolve(host), "192.168.0.0", "255.255.0.0") ||
        isInNet(dnsResolve(host), "127.0.0.0", "255.0.0.0")) {
        return "DIRECT";
    }

    var bypassNetworks = {{.NetworkList}};
    if (bypassNetworks.length > 0) {
        var resolved = dnsResolve(host);
        if (resolved) {
            for (var i = 0; i < bypassNetworks.length; i++) {
                if (isInNet(resolved, bypassNetworks[i].network, bypassNetworks[i].mask)) {
                    return "DIRECT";
                }
            }
        }
    }

    // ================================================================
    // WHITELIST (Always allow, even if blocked by category)
    // ================================================================

    var allowedDomains = {{.AllowedList}};
    for (var i = 0; i < allowedDomains.length; i++) {
        if (domainMatches(lhost, allowedDomains[i])) {
            return {{.ProxyLiteral}};
        }
    }

    // ================================================================
    // BLOCKLIST (Explicit blocks - return proxy to block)
    // ================================================================

    var blockedDomains = {{.BlockedList}};
    for (var i = 0; i < blockedDomains.length; i++) {
        if (domainMatches(lhost, blockedDomains[i])) {
            // Return proxy so it can block with proper error message
            return {{.ProxyLiteral}};
        }
    }

    var blockedKeywords = {{.KeywordList}};
    for (var i = 0; i < blockedKeywords.length; i++) {
        if (lurl.indexOf(blockedKeywords[i].toLowerCase()) !== -1) {
            return {{.ProxyLiteral}};
        }
    }

    // ================================================================
    // CATEGORY BLOCKING (Route through proxy for filtering)
    // ================================================================

    {{if .BlockCategories.adult}}
    // Adult content
    if (shExpMatch(lhost, "*.porn*") ||
        shExpMatch(lhost, "*.xxx") ||
        shExpMatch(lhost, "*.adult*") ||
        shExpMatch(lhost, "*pornhub*") ||
        shExpMatch(lhost, "*xvideos*") ||
        shExpMatch(lhost, "*xnxx*") ||
        shExpMatch(lhost, "*redtube*") ||
        shExpMatch(lhost, "*youporn*") ||
        shExpMatch(lurl, "*/adult/*") ||
        shExpMatch(lurl, "*/porn/*") ||
        shExpMatch(lurl, "*/xxx/*")) {
        return {{.ProxyLiteral}}; // Proxy will block
    }
    {{end}}

    {{if .BlockCategories.gambling}}
    // Gambling sites
    if (shExpMatch(lhost, "*casino*") ||
        shExpMatch(lhost, "*poker*") ||
        shExpMatch(lhost, "*gambling*") ||
        shExpMatch(lhost, "*bet365*") ||
        shExpMatch(lhost, "*fanduel*") ||
        shExpMatch(lhost, "*draftkings*") ||
        shExpMatch(lurl, "*/casino/*") ||
        shExpMatch(lurl, "*/gambling/*")) {
        return {{.ProxyLiteral}};
    }
    {{end}}

    {{if .BlockCategories.social}}
    // Social media
    if (dnsDomainIs(host, "facebook.com") ||
        dnsDomainIs(host, "instagram.com") ||
        dnsDomainIs(host, "twitter.com") ||
        dnsDomainIs(host, "x.com") ||
        dnsDomainIs(host, "tiktok.com") ||
        dnsDomainIs(host, "snapchat.com") ||
        dnsDomainIs(host, "reddit.com") ||
        shExpMatch(host, "*.facebook.com") ||
        shExpMatch(host, "*.instagram.com") ||
        shExpMatch(host, "*.twitter.com") ||
        shExpMatch(host, "*.tiktok.com")) {
        return {{.ProxyLiteral}};
    }
    {{end}}

    {{if .BlockCategories.streaming}}
    // Video streaming
    if (dnsDomainIs(host, "youtube.com") ||
        dnsDomainIs(host, "youtu.be") ||
        dnsDomainIs(host, "netflix.com") ||
        dnsDomainIs(host, "hulu.com") ||
        dnsDomainIs(host, "twitch.tv") ||
        shExpMatch(host, "*.youtube.com") ||
        shExpMatch(host, "*.netflix.com") ||
        shExpMatch(host, "*.hulu.com") ||
        shExpMatch(host, "*.twitch.tv")) {
        return {{.ProxyLiteral}};
    }
    {{end}}

    {{if .BlockCategories.piracy}}
    // Piracy/Torrents
    if (shExpMatch(lhost, "*torrent*") ||
        shExpMatch(lhost, "*pirate*") ||
        shExpMatch(lhost, "*rarbg*") ||
        shExpMatch(lhost, "*1337x*") ||
        shExpMatch(lurl, "*.torrent") ||
        shExpMatch(lurl, "*magnet:*")) {
        return {{.ProxyLiteral}};
    }
    {{end}}

    {{if .BlockCategories.crypto}}
    // Crypto mining
    if (shExpMatch(lhost, "*coinhive*") ||
        shExpMatch(lhost, "*crypto-loot*") ||
        shExpMatch(lhost, "*jsecoin*") ||
        shExpMatch(lurl, "*/crypto*mine*")) {
        return {{.ProxyLiteral}};
    }
    {{end}}

    {{if .BlockCategories.ads}}
    // Ads/Tracking
    if (shExpMatch(lhost, "*doubleclick*") ||
        shExpMatch(lhost, "*googlesyndication*") ||
        shExpMatch(lhost, "*googleadservices*") ||
        shExpMatch(lhost, "*.ads.*") ||
        shExpMatch(lhost, "*analytics*") ||
        shExpMatch(lhost, "*tracking*")) {
        return {{.ProxyLiteral}};
    }
    {{end}}

    // ================================================================
    // BYPASS DOMAINS (Go direct, skip proxy completely)
    // ================================================================

    var bypassDomains = {{.BypassList}};
    for (var i = 0; i < bypassDomains.length; i++) {
        if (domainMatches(lhost, bypassDomains[i])) {
            return "DIRECT";
        }
    }

    var directDomains = {{.DirectList}};
    for (var i = 0; i < directDomains.length; i++) {
        if (domainMatches(lhost, directDomains[i])) {
            return "DIRECT";
        }
    }

    {{if .Policy.BlockWorkHours}}
    // ================================================================
    // TIME-BASED BLOCKING (Work hours)
    // ================================================================

    var now = new Date();
    var hour = now.getHours();
    var isWorkHours = (hour >= {{.Policy.WorkHoursStart}} && hour < {{.Policy.WorkHoursEnd}});
    var isWeekday = (now.getDay() >= 1 && now.getDay() <= 5);

    if (isWorkHours && isWeekday) {
        // During work hours, route streaming/social through proxy for blocking
        if (shExpMatch(lhost, "*youtube*") ||
            shExpMatch(lhost, "*netflix*") ||
            shExpMatch(lhost, "*facebook*") ||
            shExpMatch(lhost, "*twitter*") ||
            shExpMatch(lhost, "*instagram*")) {
            return {{.ProxyLiteral}};
        }
    }
    {{end}}

    // ================================================================
    // DEFAULT (Route through proxy for security scanning)
    // ================================================================

    return {{.ProxyLiteral}};
}

`
