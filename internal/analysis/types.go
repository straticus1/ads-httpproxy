// Package analysis implements bounded asynchronous inspection of sampled traffic.
// It does not make request-time enforcement decisions. Callers must supply tenant
// and subject identifiers from verified identity, never from untrusted headers.
package analysis

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"time"
)

type Config struct {
	Enabled            bool    `json:"enabled" yaml:"enabled"`
	Workers            int     `json:"workers" yaml:"workers"`
	QueueCapacity      int     `json:"queue_capacity" yaml:"queue_capacity"`
	SampleRate         float64 `json:"sample_rate" yaml:"sample_rate"`
	PerTenantPerMinute int     `json:"per_tenant_per_minute" yaml:"per_tenant_per_minute"`
	MaxTenants         int     `json:"max_tenants" yaml:"max_tenants"`
	CaptureBodies      bool    `json:"capture_bodies" yaml:"capture_bodies"`
	MaxBodyBytes       int     `json:"max_body_bytes" yaml:"max_body_bytes"`
	FindingsCapacity   int     `json:"findings_capacity" yaml:"findings_capacity"`
	JournalPath        string  `json:"journal_path" yaml:"journal_path"`
	JournalMaxBytes    int64   `json:"journal_max_bytes" yaml:"journal_max_bytes"`
	MaxRetries         int     `json:"max_retries" yaml:"max_retries"`
	FindingTTLSeconds  int     `json:"finding_ttl_seconds" yaml:"finding_ttl_seconds"`
}

func defaults(c Config) Config {
	if c.Workers == 0 {
		c.Workers = 2
	}
	if c.QueueCapacity == 0 {
		c.QueueCapacity = 256
	}
	if c.SampleRate == 0 {
		c.SampleRate = 1
	}
	if c.PerTenantPerMinute == 0 {
		c.PerTenantPerMinute = 1000
	}
	if c.MaxTenants == 0 {
		c.MaxTenants = 1024
	}
	if c.MaxBodyBytes == 0 {
		c.MaxBodyBytes = 4096
	}
	if c.FindingsCapacity == 0 {
		c.FindingsCapacity = 1000
	}
	if c.JournalMaxBytes == 0 {
		c.JournalMaxBytes = 10 << 20
	}
	if c.FindingTTLSeconds == 0 {
		c.FindingTTLSeconds = 3600
	}
	return c
}

func Validate(cfg Config) error {
	c := defaults(cfg)
	if c.Workers < 1 || c.Workers > 32 {
		return fmt.Errorf("analysis workers must be between 1 and 32")
	}
	if c.QueueCapacity < 1 || c.QueueCapacity > 10000 {
		return fmt.Errorf("analysis queue_capacity must be between 1 and 10000")
	}
	if math.IsNaN(c.SampleRate) || math.IsInf(c.SampleRate, 0) || c.SampleRate < 0 || c.SampleRate > 1 {
		return fmt.Errorf("analysis sample_rate must be between 0 and 1 (zero defaults to 1)")
	}
	if c.PerTenantPerMinute < 1 || c.PerTenantPerMinute > 1000000 || c.MaxTenants < 1 || c.MaxTenants > 10000 {
		return fmt.Errorf("analysis tenant budgets exceed supported bounds")
	}
	if c.MaxBodyBytes < 1 || c.MaxBodyBytes > 65536 || c.FindingsCapacity < 1 || c.FindingsCapacity > 10000 {
		return fmt.Errorf("analysis body/findings bounds invalid")
	}
	if c.JournalMaxBytes < 65536 || c.JournalMaxBytes > 1<<30 {
		return fmt.Errorf("analysis journal_max_bytes must be between 65536 and 1073741824")
	}
	if c.MaxRetries < 0 || c.MaxRetries > 3 {
		return fmt.Errorf("analysis max_retries must be between 0 and 3")
	}
	if c.FindingTTLSeconds < 1 || c.FindingTTLSeconds > 86400*30 {
		return fmt.Errorf("analysis finding_ttl_seconds must be between 1 and 2592000")
	}
	return nil
}

// Event values are copied and sanitized on submission. A worker never owns the
// live request body. Sampling must use separately bounded previews.
type Event struct {
	ID              string      `json:"id"`
	Tenant          string      `json:"tenant"`
	Subject         string      `json:"subject,omitempty"`
	Method          string      `json:"method"`
	URL             string      `json:"url"`
	Status          int         `json:"status"`
	Decision        string      `json:"decision,omitempty"`
	Reason          string      `json:"reason,omitempty"`
	RequestHeaders  http.Header `json:"request_headers,omitempty"`
	ResponseHeaders http.Header `json:"response_headers,omitempty"`
	RequestBody     string      `json:"request_body,omitempty"`
	ResponseBody    string      `json:"response_body,omitempty"`
	Timestamp       time.Time   `json:"timestamp"`
	PolicyVersion   string      `json:"policy_version,omitempty"`
}

type Finding struct {
	ID            string            `json:"id"`
	EventID       string            `json:"event_id"`
	Tenant        string            `json:"tenant"`
	Subject       string            `json:"subject,omitempty"`
	URL           string            `json:"url"`
	Category      string            `json:"category"`
	Confidence    float64           `json:"confidence"`
	Reason        string            `json:"reason"`
	CreatedAt     time.Time         `json:"created_at"`
	ExpiresAt     time.Time         `json:"expires_at"`
	PolicyVersion string            `json:"policy_version,omitempty"`
	ModelVersion  string            `json:"model_version"`
	Evidence      map[string]string `json:"evidence,omitempty"`
}

type Filter struct {
	Tenant         string
	Category       string
	Limit          int
	IncludeExpired bool
}

// Analyzer must honor context cancellation and return at most 32 findings.
// Implementations are called concurrently and must be safe for parallel use.
type Analyzer interface {
	Analyze(context.Context, Event) ([]Finding, error)
}

type Stats struct {
	Received         uint64 `json:"received"`
	SampledOut       uint64 `json:"sampled_out"`
	Accepted         uint64 `json:"accepted"`
	DroppedBudget    uint64 `json:"dropped_budget"`
	DroppedQueue     uint64 `json:"dropped_queue"`
	DroppedTenant    uint64 `json:"dropped_tenant"`
	DroppedClosed    uint64 `json:"dropped_closed"`
	Errors           uint64 `json:"errors"`
	Retries          uint64 `json:"retries"`
	Completed        uint64 `json:"completed"`
	JournalErrors    uint64 `json:"journal_errors"`
	QueueDepth       int    `json:"queue_depth"`
	RetainedFindings int    `json:"retained_findings"`
}
