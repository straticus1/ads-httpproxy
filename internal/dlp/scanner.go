package dlp

import (
	"regexp"
	"sync"
)

// Scanner defines the interface for DLP scanning.
type Scanner interface {
	// Scan returns true if sensitive data is found, along with a description of the finding.
	Scan(data []byte) (bool, string)
}

// RegexScanner implements Scanner using regular expressions.
type RegexScanner struct {
	rules []*regexp.Regexp
	mu    sync.RWMutex
}

// NewRegexScanner creates a new scanner with the given regex patterns.
func NewRegexScanner(patterns []string) (*RegexScanner, error) {
	var rules []*regexp.Regexp
	for _, p := range patterns {
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, err
		}
		rules = append(rules, re)
	}
	return &RegexScanner{rules: rules}, nil
}

func (s *RegexScanner) Scan(data []byte) (bool, string) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, rule := range s.rules {
		if rule.Match(data) {
			return true, "Matched pattern: " + rule.String()
		}
	}
	return false, ""
}
