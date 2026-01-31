package policy

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"ads-httpproxy/pkg/logging"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker/decls"
	"go.uber.org/zap"
)

// Policy represents a single access control rule
type Policy struct {
	ID        string      `yaml:"id"`
	Effect    string      `yaml:"effect"` // "allow", "block", "log"
	Condition string      `yaml:"condition"`
	Actions   []string    `yaml:"actions"` // Additional actions e.g., "rate_limit", "redact_headers"
	Program   cel.Program `yaml:"-"`
}

// EvalContext defines the data available to CEL expressions
type EvalContext struct {
	Request ClientRequest `json:"request"`
	Client  ClientInfo    `json:"client"`
	User    UserInfo      `json:"user"`
	Time    TimeInfo      `json:"time"`
}

type ClientRequest struct {
	Method   string            `json:"method"`
	URL      string            `json:"url"`
	Host     string            `json:"host"`
	Path     string            `json:"path"`
	Headers  map[string]string `json:"headers"`
	Protocol string            `json:"protocol"`
}

type ClientInfo struct {
	IP      string `json:"ip"`
	Port    string `json:"port"`
	Country string `json:"country"` // Requires GeoIP integration
}

type UserInfo struct {
	Username string   `json:"username"`
	Groups   []string `json:"groups"`
}

type TimeInfo struct {
	Year      int `json:"year"`
	Month     int `json:"month"`
	Day       int `json:"day"`
	Hour      int `json:"hour"`
	Minute    int `json:"minute"`
	DayOfWeek int `json:"day_of_week"` // 0=Sunday, 6=Saturday
}

// Engine manages policies and evaluation
type Engine struct {
	env      *cel.Env
	policies []*Policy
	mu       sync.RWMutex
	pool     sync.Pool
}

// NewEngine creates a new policy engine
func NewEngine() (*Engine, error) {
	// Define CEL environment with context variables
	env, err := cel.NewEnv(
		cel.Declarations(
			decls.NewVar("request", decls.NewMapType(decls.String, decls.Dyn)),
			decls.NewVar("client", decls.NewMapType(decls.String, decls.Dyn)),
			decls.NewVar("user", decls.NewMapType(decls.String, decls.Dyn)),
			decls.NewVar("time", decls.NewMapType(decls.String, decls.Dyn)),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create CEL env: %w", err)
	}

	return &Engine{
		env:      env,
		policies: []*Policy{},
		pool: sync.Pool{
			New: func() interface{} {
				// Pre-allocate nested structure
				return map[string]interface{}{
					"request": make(map[string]interface{}),
					"client":  make(map[string]interface{}),
					"user":    make(map[string]interface{}),
					"time":    make(map[string]interface{}),
				}
			},
		},
	}, nil
}

// ... LoadFromFile ...

// Evaluate checks all policies against the context
// Returns: allowed (bool), matched (bool), actions ([]string), reason (string)
func (e *Engine) Evaluate(ctx context.Context, evalCtx *EvalContext) (bool, bool, []string, string) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	// 1. Get from Pool
	input := e.pool.Get().(map[string]interface{})
	defer e.pool.Put(input)

	// 2. Populate (Safe reuse of maps)
	reqMap := input["request"].(map[string]interface{})
	reqMap["method"] = evalCtx.Request.Method
	reqMap["url"] = evalCtx.Request.URL
	reqMap["host"] = evalCtx.Request.Host
	reqMap["path"] = evalCtx.Request.Path
	reqMap["headers"] = evalCtx.Request.Headers
	reqMap["protocol"] = evalCtx.Request.Protocol

	clientMap := input["client"].(map[string]interface{})
	clientMap["ip"] = evalCtx.Client.IP
	clientMap["port"] = evalCtx.Client.Port
	clientMap["country"] = evalCtx.Client.Country

	userMap := input["user"].(map[string]interface{})
	userMap["username"] = evalCtx.User.Username
	userMap["groups"] = evalCtx.User.Groups

	timeMap := input["time"].(map[string]interface{})
	timeMap["year"] = evalCtx.Time.Year
	timeMap["month"] = evalCtx.Time.Month
	timeMap["day"] = evalCtx.Time.Day
	timeMap["hour"] = evalCtx.Time.Hour
	timeMap["minute"] = evalCtx.Time.Minute
	timeMap["day_of_week"] = evalCtx.Time.DayOfWeek

	// Default: Allow

	for _, p := range e.policies {
		out, _, err := p.Program.Eval(input)
		if err != nil {
			logging.Logger.Warn("Policy evaluation error", zap.String("id", p.ID), zap.Error(err))
			continue
		}

		if matched, ok := out.Value().(bool); ok && matched {
			logging.Logger.Debug("Policy Matched", zap.String("id", p.ID), zap.String("effect", p.Effect))

			if strings.EqualFold(p.Effect, "block") {
				return false, true, p.Actions, fmt.Sprintf("Blocked by policy %s", p.ID)
			}

			// If allowed, we might continue to see if any block rule triggers later?
			// Usually "First Match" or "Deny Overrides".
			// Let's implement Deny Overrides / Block Priority.
			// Currently iterating: if Block -> Return immediately.
			// If Allow -> Continue? Or Return?
			// Simplest: First Match.
			return true, true, p.Actions, fmt.Sprintf("Allowed by policy %s", p.ID)
		}
	}

	// No policy matched -> Default Allow (or should be Block?)
	// Usually proxy is Default Allow unless blocked.
	return true, false, nil, "No policy matched"
}

// Helper to construct context from HTTP Request
func NewEvalContext(req *http.Request, username string, group string) *EvalContext {
	host := req.Host
	// Helper to get Year/Month/etc
	now := time.Now()

	headers := make(map[string]string)
	for k, v := range req.Header {
		if len(v) > 0 {
			headers[k] = v[0]
		}
	}

	groups := []string{}
	if group != "" {
		groups = append(groups, group)
	}

	return &EvalContext{
		Request: ClientRequest{
			Method:   req.Method,
			URL:      req.URL.String(),
			Host:     host,
			Path:     req.URL.Path,
			Headers:  headers,
			Protocol: req.Proto,
		},
		Time: TimeInfo{
			Year:      now.Year(),
			Month:     int(now.Month()),
			Day:       now.Day(),
			Hour:      now.Hour(),
			Minute:    now.Minute(),
			DayOfWeek: int(now.Weekday()),
		},
		User: UserInfo{
			Username: username,
			Groups:   groups,
		},
		// Client info usually needs IP extraction logic passed in or done here
	}
}
