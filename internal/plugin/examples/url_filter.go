package examples

import (
	"net/http"
	"regexp"
	"strings"

	"ads-httpproxy/internal/plugin"
	"ads-httpproxy/pkg/logging"

	"github.com/elazarl/goproxy"
	"go.uber.org/zap"
)

// URLFilterPlugin blocks requests matching specific patterns
type URLFilterPlugin struct {
	BlockedDomains  []string         // Exact domain matches
	BlockedPatterns []*regexp.Regexp // Regex patterns
	AllowedDomains  []string         // Whitelist (checked first)
	BlockMessage    string
}

func NewURLFilterPlugin(blockedDomains, blockedPatterns, allowedDomains []string) (*URLFilterPlugin, error) {
	plugin := &URLFilterPlugin{
		BlockedDomains: blockedDomains,
		AllowedDomains: allowedDomains,
		BlockMessage:   "Access Denied: URL Blocked by Plugin",
	}

	// Compile regex patterns
	for _, pattern := range blockedPatterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, err
		}
		plugin.BlockedPatterns = append(plugin.BlockedPatterns, re)
	}

	return plugin, nil
}

func (p *URLFilterPlugin) Name() string {
	return "url-filter"
}

func (p *URLFilterPlugin) OnRequest(req *http.Request, ctx *plugin.Context) (*http.Request, *http.Response) {
	if req == nil || req.URL == nil {
		return req, nil
	}

	host := req.URL.Hostname()
	fullURL := req.URL.String()

	// Check whitelist first (exact match or subdomain)
	for _, allowed := range p.AllowedDomains {
		if matchesDomain(host, allowed) {
			return req, nil
		}
	}

	// Check blocked domains (exact match or subdomain)
	for _, blocked := range p.BlockedDomains {
		if matchesDomain(host, blocked) {
			logging.Logger.Warn("Plugin: Blocked domain",
				zap.String("plugin", p.Name()),
				zap.String("domain", host),
				zap.String("url", fullURL))
			return req, goproxy.NewResponse(req, goproxy.ContentTypeText, http.StatusForbidden, p.BlockMessage)
		}
	}

	// Check blocked patterns
	for _, pattern := range p.BlockedPatterns {
		if pattern.MatchString(fullURL) {
			logging.Logger.Warn("Plugin: Blocked pattern",
				zap.String("plugin", p.Name()),
				zap.String("pattern", pattern.String()),
				zap.String("url", fullURL))
			return req, goproxy.NewResponse(req, goproxy.ContentTypeText, http.StatusForbidden, p.BlockMessage)
		}
	}

	return req, nil
}

// matchesDomain checks if host matches domain (exact or subdomain)
// e.g., "evil.com" matches "evil.com" and "www.evil.com" but not "notevil.com"
func matchesDomain(host, domain string) bool {
	host = strings.ToLower(host)
	domain = strings.ToLower(domain)

	// Exact match
	if host == domain {
		return true
	}

	// Subdomain match (must have . prefix)
	if strings.HasSuffix(host, "."+domain) {
		return true
	}

	return false
}

func (p *URLFilterPlugin) OnResponse(resp *http.Response, ctx *plugin.Context) *http.Response {
	// No response filtering
	return resp
}
