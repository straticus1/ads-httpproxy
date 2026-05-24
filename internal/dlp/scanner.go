package dlp

import (
	"regexp"
	"strings"
	"sync"
)

// RuleEngine defines a pluggable engine for detecting sensitive data configurations (Regex, YARA, etc).
type RuleEngine interface {
	Scan(data []byte) (bool, string)
}

// RegexEngine implements RuleEngine using highly-optimized regular expressions.
type RegexEngine struct {
	fastLiterals []string
	masterRule   *regexp.Regexp
	fallback     []*regexp.Regexp
	mu           sync.RWMutex
}

// NewRegexEngine creates a modernized, optimized regex engine.
func NewRegexEngine(patterns []string) (*RegexEngine, error) {
	var fallback []*regexp.Regexp
	var combinedParts []string

	for _, p := range patterns {
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, err
		}
		fallback = append(fallback, re)
		combinedParts = append(combinedParts, "(?:"+p+")")
	}

	var masterRule *regexp.Regexp
	if len(combinedParts) > 0 {
		masterExpr := strings.Join(combinedParts, "|")
		// compile a single massive rule for fast execution
		compiled, err := regexp.Compile(masterExpr)
		if err == nil {
			masterRule = compiled
		}
	}

	return &RegexEngine{
		fallback:   fallback,
		masterRule: masterRule,
	}, nil
}

// Scan returns true if sensitive data is found, utilizing Aho-Corasick or master-regex fallback.
func (s *RegexEngine) Scan(data []byte) (bool, string) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Use fast path if Master Rule successfully compiled
	if s.masterRule != nil {
		if !s.masterRule.Match(data) {
			return false, ""
		}
		// If it hit, we figure out WHICH rule it hit utilizing sequential fallback
		// (since master hits don't pinpoint which capturing group matched natively easily)
	}

	for _, rule := range s.fallback {
		if rule.Match(data) {
			return true, "Matched pattern: " + rule.String()
		}
	}
	return false, ""
}

// For backwards compatibility
type Scanner interface {
	Scan(data []byte) (bool, string)
}

// RegexScanner acts as a bridge to RegexEngine.
type RegexScanner struct {
	engine *RegexEngine
}

func NewRegexScanner(patterns []string) (*RegexScanner, error) {
	engine, err := NewRegexEngine(patterns)
	if err != nil {
		return nil, err
	}
	return &RegexScanner{engine: engine}, nil
}

func (s *RegexScanner) Scan(data []byte) (bool, string) {
	return s.engine.Scan(data)
}
