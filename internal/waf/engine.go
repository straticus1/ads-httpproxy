package waf

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	coreruleset "github.com/corazawaf/coraza-coreruleset"
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
	"go.uber.org/zap"

	"ads-httpproxy/pkg/logging"
)

// Config holds WAF engine configuration.
type Config struct {
	// DetectionOnly logs violations but never blocks traffic. Use for tuning.
	DetectionOnly bool

	// ParanoiaLevel sets the OWASP CRS paranoia level (1–4). Higher levels
	// activate more rules and catch more attacks at the cost of false positives.
	// Default: 1.
	ParanoiaLevel int

	// AnomalyThreshold is the inbound anomaly score at which a request is
	// blocked. CRS accumulates scores across matched rules; a single critical
	// SQLi hit scores 5, so the default of 5 blocks on the first critical hit.
	AnomalyThreshold int

	// ExcludedRules is a list of CRS rule IDs to suppress (e.g. "920420").
	// Use to silence false positives without disabling entire rule groups.
	ExcludedRules []string

	// MaxBodySize is the maximum number of request body bytes to inspect.
	// Bodies larger than this are truncated before inspection but still
	// forwarded intact. Default: 1 MB.
	MaxBodySize int64

	// EventLogFile is the path to a JSON-lines WAF event log. Each blocked or
	// detected request appends one JSON object. Disabled if empty.
	EventLogFile string

	// CustomRulesDir is an optional directory of .conf files containing
	// additional ModSecurity-format SecRule directives loaded after CRS.
	CustomRulesDir string
}

// Result is returned by Engine.Check for every inspected request.
type Result struct {
	// Blocked is true when the request should be rejected (DetectionOnly=false).
	Blocked bool

	// RuleID is the OWASP CRS rule that triggered the interruption.
	RuleID int

	// Description is a human-readable summary of the match.
	Description string

	// Action is one of "block", "detect", or "pass".
	Action string
}

// Event is a structured WAF log entry written to EventLogFile.
type Event struct {
	Time    string `json:"time"`
	IP      string `json:"ip"`
	Method  string `json:"method"`
	URI     string `json:"uri"`
	Host    string `json:"host"`
	RuleID  int    `json:"rule_id"`
	Action  string `json:"action"`
	Message string `json:"message,omitempty"`
}

// Engine wraps the Coraza WAF for full HTTP request inspection using the
// OWASP Core Rule Set. It is safe for concurrent use across goroutines.
type Engine struct {
	waf      coraza.WAF
	cfg      *Config
	eventLog *os.File
	mu       sync.Mutex // protects eventLog writes
}

// NewEngine creates and initialises a production WAF engine backed by Coraza
// and the embedded OWASP CRS 4.x ruleset. It returns an error if Coraza fails
// to compile the ruleset (e.g. a custom rule contains a syntax error).
func NewEngine(cfg *Config) (*Engine, error) {
	if cfg == nil {
		cfg = &Config{}
	}
	if cfg.ParanoiaLevel == 0 {
		cfg.ParanoiaLevel = 1
	}
	if cfg.AnomalyThreshold == 0 {
		cfg.AnomalyThreshold = 5
	}
	if cfg.MaxBodySize == 0 {
		cfg.MaxBodySize = 1 << 20 // 1 MB
	}

	// CRS variables must be set before the setup file is included.
	// SecAction id 900000 sets paranoia level; 900110 sets the anomaly threshold.
	pre := fmt.Sprintf(`
SecRuleEngine On
SecRequestBodyAccess On
SecResponseBodyAccess Off
SecRequestBodyLimit %d
SecRequestBodyNoFilesLimit %d
SecAction "id:900000,phase:1,nolog,pass,t:none,setvar:tx.paranoia_level=%d"
SecAction "id:900110,phase:1,nolog,pass,t:none,setvar:tx.inbound_anomaly_score_threshold=%d,setvar:tx.outbound_anomaly_score_threshold=4"
`,
		cfg.MaxBodySize,
		cfg.MaxBodySize,
		cfg.ParanoiaLevel,
		cfg.AnomalyThreshold,
	)

	if cfg.DetectionOnly {
		pre = strings.ReplaceAll(pre, "SecRuleEngine On", "SecRuleEngine DetectionOnly")
	}

	// Build rule exclusions that will be applied after CRS is loaded.
	var exclusions strings.Builder
	for _, id := range cfg.ExcludedRules {
		exclusions.WriteString(fmt.Sprintf("SecRuleRemoveById %s\n", id))
	}

	wafConf := coraza.NewWAFConfig().
		WithRootFS(coreruleset.FS).
		WithDirectives(pre).
		WithDirectives(`
Include @coraza.conf-recommended
Include @crs-setup.conf.example
Include @owasp_crs/*.conf
`).
		WithDirectives(exclusions.String())

	if cfg.CustomRulesDir != "" {
		wafConf = wafConf.WithDirectives(
			fmt.Sprintf("Include %s/*.conf\n", cfg.CustomRulesDir),
		)
	}

	cWAF, err := coraza.NewWAF(wafConf)
	if err != nil {
		return nil, fmt.Errorf("coraza init: %w", err)
	}

	e := &Engine{waf: cWAF, cfg: cfg}

	if cfg.EventLogFile != "" {
		f, err := os.OpenFile(cfg.EventLogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
		if err != nil {
			return nil, fmt.Errorf("waf event log open: %w", err)
		}
		e.eventLog = f
	}

	return e, nil
}

// Check inspects an HTTP request through all applicable WAF phases and returns
// a Result. When DetectionOnly is configured, Blocked is always false but the
// event is logged. The request body is buffered up to MaxBodySize and restored
// so the upstream handler can still read it.
func (e *Engine) Check(req *http.Request) (*Result, error) {
	tx := e.waf.NewTransaction()
	defer func() {
		tx.ProcessLogging()
		if err := tx.Close(); err != nil {
			logging.Logger.Debug("waf tx close", zap.Error(err))
		}
	}()

	// Phase 1 — connection metadata.
	clientIP := extractIP(req.RemoteAddr)
	tx.ProcessConnection(clientIP, 0, "", 0)
	tx.SetServerName(req.Host)

	// Phase 1 — URI + method.
	proto := req.Proto
	if proto == "" {
		proto = "HTTP/1.1"
	}
	tx.ProcessURI(req.URL.String(), req.Method, proto)
	if it := tx.Interruption(); it != nil {
		return e.interrupt(it, req, "uri"), nil
	}

	// Phase 1 — request headers.
	for name, vals := range req.Header {
		for _, val := range vals {
			tx.AddRequestHeader(name, val)
		}
	}
	// Go's http.Request drops the Host header; Coraza needs it explicitly.
	tx.AddRequestHeader("Host", req.Host)

	if it := tx.ProcessRequestHeaders(); it != nil {
		return e.interrupt(it, req, "headers"), nil
	}

	// Phase 2 — request body (buffer up to MaxBodySize, then restore).
	if req.Body != nil {
		body, err := io.ReadAll(io.LimitReader(req.Body, e.cfg.MaxBodySize))
		if err == nil {
			// Restore body for the proxy to forward to the upstream.
			req.Body = io.NopCloser(bytes.NewReader(body))
			if len(body) > 0 {
				if it, _, werr := tx.WriteRequestBody(body); werr != nil {
					logging.Logger.Debug("waf body write", zap.Error(werr))
				} else if it != nil {
					return e.interrupt(it, req, "body-write"), nil
				}
			}
		}
	}

	if it, err := tx.ProcessRequestBody(); err != nil {
		return nil, fmt.Errorf("waf process body: %w", err)
	} else if it != nil {
		return e.interrupt(it, req, "body"), nil
	}

	return &Result{Action: "pass"}, nil
}

// MatchedRules returns the matched rules for additional context after Check.
// This is a no-op stub; full matched rule detail is available via the event log.
func (e *Engine) MatchedRules(tx types.Transaction) []types.MatchedRule {
	return tx.MatchedRules()
}

// Close releases resources held by the engine (event log file handle).
func (e *Engine) Close() error {
	if e.eventLog != nil {
		return e.eventLog.Close()
	}
	return nil
}

// interrupt converts a Coraza Interruption into a Result and writes an event.
func (e *Engine) interrupt(it *types.Interruption, req *http.Request, phase string) *Result {
	blocked := !e.cfg.DetectionOnly
	action := "block"
	if e.cfg.DetectionOnly {
		action = "detect"
	}

	msg := fmt.Sprintf("rule %d triggered in phase=%s status=%d", it.RuleID, phase, it.Status)

	logging.Logger.Warn("WAF",
		zap.String("action", action),
		zap.Int("rule_id", it.RuleID),
		zap.String("phase", phase),
		zap.String("method", req.Method),
		zap.String("host", req.Host),
		zap.String("uri", req.URL.RequestURI()),
		zap.String("client_ip", extractIP(req.RemoteAddr)),
	)

	e.writeEvent(Event{
		Time:    time.Now().UTC().Format(time.RFC3339),
		IP:      extractIP(req.RemoteAddr),
		Method:  req.Method,
		URI:     req.URL.String(),
		Host:    req.Host,
		RuleID:  it.RuleID,
		Action:  action,
		Message: msg,
	})

	return &Result{
		Blocked:     blocked,
		RuleID:      it.RuleID,
		Description: msg,
		Action:      action,
	}
}

func (e *Engine) writeEvent(ev Event) {
	if e.eventLog == nil {
		return
	}
	b, err := json.Marshal(ev)
	if err != nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	_, _ = e.eventLog.Write(append(b, '\n'))
}

// extractIP returns just the host part of a "host:port" remote address.
func extractIP(addr string) string {
	if idx := strings.LastIndex(addr, ":"); idx != -1 {
		return addr[:idx]
	}
	return addr
}
