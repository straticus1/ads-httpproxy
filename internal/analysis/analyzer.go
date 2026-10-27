package analysis

import (
	"context"
	"net/url"
	"regexp"
	"strings"
)

var ssnPattern = regexp.MustCompile(`\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b`)

// DefaultAnalyzer performs deterministic, explainable classification. It never
// fetches URLs or sends captured content to an external model.
type DefaultAnalyzer struct{}

func (DefaultAnalyzer) Analyze(ctx context.Context, e Event) ([]Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	category, reason := "web", "HTTP traffic observed"
	ct := strings.ToLower(e.ResponseHeaders.Get("Content-Type"))
	if strings.Contains(ct, "json") {
		category, reason = "api", "JSON response content type"
	}
	if u, err := url.Parse(e.URL); err == nil {
		switch strings.ToLower(u.Hostname()) {
		case "api.openai.com", "api.anthropic.com", "generativelanguage.googleapis.com":
			category, reason = "ai_service", "Destination matches a known AI API authority"
		}
	}
	findings := []Finding{{Category: category, Confidence: 1, Reason: reason, ModelVersion: "rules-v1"}}
	if e.Decision == "block" {
		findings = append(findings, Finding{Category: "policy_block", Confidence: 1, Reason: "Request blocked by enforcement policy", ModelVersion: "rules-v1", Evidence: map[string]string{"reason": e.Reason}})
	}
	if e.Status >= 500 {
		findings = append(findings, Finding{Category: "upstream_error", Confidence: 1, Reason: "Upstream returned a server error", ModelVersion: "rules-v1"})
	}
	if strings.Contains(e.RequestBody, "[REDACTED]") || strings.Contains(e.ResponseBody, "[REDACTED]") || ssnPattern.MatchString(e.RequestBody) || ssnPattern.MatchString(e.ResponseBody) {
		findings = append(findings, Finding{Category: "sensitive_data", Confidence: 0.9, Reason: "Sample matched a credential marker or SSN-shaped pattern; review required", ModelVersion: "rules-v1", Evidence: map[string]string{"detector": "bounded-preview-pattern"}})
	}
	return findings, nil
}
