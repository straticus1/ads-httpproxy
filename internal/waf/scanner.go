package waf

import (
	"regexp"
	"sync"
)

// Rule represents a WAF rule
type Rule struct {
	ID          string
	Description string
	Pattern     *regexp.Regexp
}

// Scanner handles WAF scanning
type Scanner struct {
	rules []Rule
	mu    sync.RWMutex
}

// NewScanner creates a new WAF scanner with default rules
func NewScanner() *Scanner {
	s := &Scanner{}
	s.loadDefaultRules()
	return s
}

func (s *Scanner) loadDefaultRules() {
	// Simple examples - in production these should be robust OWASP CRS patterns
	s.rules = []Rule{
		{
			ID:          "1001",
			Description: "SQL Injection - Generic OR",
			Pattern:     regexp.MustCompile(`(?i)'\s+OR\s+\d+=\d+`),
		},
		{
			ID:          "1002",
			Description: "SQL Injection - UNION SELECT",
			Pattern:     regexp.MustCompile(`(?i)UNION\s+SELECT`),
		},
		{
			ID:          "1003",
			Description: "XSS - Script Tag",
			Pattern:     regexp.MustCompile(`(?i)<script.*?>.*?</script>`),
		},
		{
			ID:          "1004",
			Description: "Command Injection - Generic",
			Pattern:     regexp.MustCompile(`(?i)(;|\||` + "`" + `)\s*(ls|cat|wget|curl|nc)\s+`),
		},
		{
			ID:          "1005",
			Description: "Path Traversal",
			Pattern:     regexp.MustCompile(`\.\./\.\./`),
		},
	}
}

// Scan checks content against WAF rules. Returns matching Rule ID and true if blocked.
func (s *Scanner) Scan(content string) (bool, string) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, rule := range s.rules {
		if rule.Pattern.MatchString(content) {
			return true, rule.Description
		}
	}
	return false, ""
}

// AddRule adds a custom rule
func (s *Scanner) AddRule(id, desc, pattern string) error {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rules = append(s.rules, Rule{
		ID:          id,
		Description: desc,
		Pattern:     re,
	})
	return nil
}
