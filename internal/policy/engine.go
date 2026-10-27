package policy

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"ads-httpproxy/pkg/logging"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker/decls"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
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
	VerifiedMTLS bool   `json:"verified_mtls"`
	IP           string `json:"ip"`
	Port         string `json:"port"`
	Country      string `json:"country"` // Requires GeoIP integration
}

type UserInfo struct {
	Subject  string   `json:"subject"`
	Issuer   string   `json:"issuer"`
	Tenant   string   `json:"tenant"`
	Scopes   []string `json:"scopes"`
	AMR      []string `json:"amr"`
	ACR      string   `json:"acr"`
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
	defaultBlock bool
	env          *cel.Env
	policies     []*Policy
	mu           sync.RWMutex
	pool         sync.Pool
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

// LoadFromFile atomically replaces the active policies with policies compiled
// from a YAML file. The file may contain either a top-level `policies` field or
// a bare policy list.
func (e *Engine) LoadFromFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read policy file: %w", err)
	}
	var document struct {
		Policies []*Policy `yaml:"policies"`
	}
	if err := yaml.Unmarshal(data, &document); err != nil {
		return fmt.Errorf("parse policy file: %w", err)
	}
	policies := document.Policies
	if policies == nil {
		if err := yaml.Unmarshal(data, &policies); err != nil {
			return fmt.Errorf("parse policy list: %w", err)
		}
	}
	compiled := make([]*Policy, 0, len(policies))
	for index, item := range policies {
		if item == nil || strings.TrimSpace(item.ID) == "" || strings.TrimSpace(item.Condition) == "" {
			return fmt.Errorf("policy %d requires id and condition", index)
		}
		switch strings.ToLower(item.Effect) {
		case "allow", "block", "log":
		default:
			return fmt.Errorf("policy %q has unsupported effect %q", item.ID, item.Effect)
		}
		for _, action := range item.Actions {
			name, arg, _ := strings.Cut(action, ":")
			switch name {
			case "rate_limit":
				n, err := strconv.Atoi(arg)
				if err != nil || n < 1 || n > 100000 {
					return fmt.Errorf("invalid rate_limit action")
				}
			case "redact_headers":
				if arg == "" {
					return fmt.Errorf("redact_headers requires header names")
				}
				for _, h := range strings.Split(arg, ",") {
					h = strings.TrimSpace(h)
					if h == "" || strings.ContainsAny(h, " \r\n:") {
						return fmt.Errorf("invalid header action")
					}
				}
			default:
				return fmt.Errorf("unsupported policy action %q", action)
			}
		}
		ast, issues := e.env.Compile(item.Condition)
		if issues != nil && issues.Err() != nil {
			return fmt.Errorf("compile policy %q: %w", item.ID, issues.Err())
		}
		if ast.OutputType().String() != "bool" {
			return fmt.Errorf("policy %q condition must return bool", item.ID)
		}
		program, err := e.env.Program(ast, cel.CostLimit(10000), cel.InterruptCheckFrequency(100))
		if err != nil {
			return fmt.Errorf("create policy %q: %w", item.ID, err)
		}
		copy := *item
		copy.Program = program
		compiled = append(compiled, &copy)
	}
	e.mu.Lock()
	e.policies = compiled
	e.mu.Unlock()
	return nil
}

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
	clientMap["verified_mtls"] = evalCtx.Client.VerifiedMTLS

	userMap := input["user"].(map[string]interface{})
	userMap["username"] = evalCtx.User.Username
	userMap["groups"] = evalCtx.User.Groups
	userMap["subject"] = evalCtx.User.Subject
	userMap["issuer"] = evalCtx.User.Issuer
	userMap["tenant"] = evalCtx.User.Tenant
	userMap["scopes"] = evalCtx.User.Scopes
	userMap["amr"] = evalCtx.User.AMR
	userMap["acr"] = evalCtx.User.ACR

	timeMap := input["time"].(map[string]interface{})
	timeMap["year"] = evalCtx.Time.Year
	timeMap["month"] = evalCtx.Time.Month
	timeMap["day"] = evalCtx.Time.Day
	timeMap["hour"] = evalCtx.Time.Hour
	timeMap["minute"] = evalCtx.Time.Minute
	timeMap["day_of_week"] = evalCtx.Time.DayOfWeek

	// Default: Allow

	for _, p := range e.policies {
		out, _, err := p.Program.ContextEval(ctx, input)
		if err != nil {
			logging.Logger.Warn("Policy evaluation error", zap.String("id", p.ID), zap.Error(err))
			return false, true, nil, "Policy evaluation failed: " + p.ID
		}

		if matched, ok := out.Value().(bool); ok && matched {
			if strings.EqualFold(p.Effect, "log") {
				logging.Logger.Info("Policy observed", zap.String("id", p.ID))
				continue
			}
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
	return !e.defaultBlock, false, nil, "No policy matched"
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

	clientIP, clientPort, _ := net.SplitHostPort(req.RemoteAddr)
	return &EvalContext{
		Client: ClientInfo{IP: clientIP, Port: clientPort},
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

func (e *Engine) SetDefaultEffect(effect string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.defaultBlock = effect == "" || effect == "block"
}
