package policy

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
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
	ID        string      `yaml:"id" json:"id"`
	Effect    string      `yaml:"effect" json:"effect"` // "allow", "block", "log"
	Condition string      `yaml:"condition" json:"condition"`
	Actions   []string    `yaml:"actions" json:"actions,omitempty"` // Additional actions e.g., "rate_limit", "redact_headers"
	Program   cel.Program `yaml:"-" json:"-"`
}

// EvalContext defines the data available to CEL expressions
type EvalContext struct {
	ValidationError string        `json:"-"`
	Request         ClientRequest `json:"request"`
	Client          ClientInfo    `json:"client"`
	User            UserInfo      `json:"user"`
	Time            TimeInfo      `json:"time"`
}

type ClientRequest struct {
	Hostname string            `json:"hostname"`
	Port     int               `json:"port"`
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
	version      uint64
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
		CIDREnvOption(),
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
	var node yaml.Node
	if err := yaml.Unmarshal(data, &node); err != nil {
		return fmt.Errorf("parse policy file: %w", err)
	}
	if len(node.Content) != 1 {
		return fmt.Errorf("empty policy document")
	}
	var policies []*Policy
	if node.Content[0].Kind == yaml.SequenceNode {
		if err := node.Decode(&policies); err != nil {
			return err
		}
	} else {
		var document struct {
			Policies []*Policy `yaml:"policies"`
		}
		if err := node.Decode(&document); err != nil {
			return err
		}
		if document.Policies == nil {
			return fmt.Errorf("policy document requires policies")
		}
		policies = document.Policies
	}
	snapshot := e.Snapshot()
	_, err = e.Replace(snapshot.Version, policies, snapshot.DefaultEffect)
	return err
}

func (e *Engine) compile(policies []*Policy) ([]*Policy, error) {
	seen := make(map[string]bool)
	compiled := make([]*Policy, 0, len(policies))
	for index, item := range policies {
		if item == nil || strings.TrimSpace(item.ID) == "" || strings.TrimSpace(item.Condition) == "" {
			return nil, fmt.Errorf("policy %d requires id and condition", index)
		}
		switch strings.ToLower(item.Effect) {
		case "allow", "block", "log":
		default:
			return nil, fmt.Errorf("policy %q has unsupported effect %q", item.ID, item.Effect)
		}
		if seen[item.ID] {
			return nil, fmt.Errorf("duplicate policy id %q", item.ID)
		}
		seen[item.ID] = true
		if _, err := parseObligations(item.Actions); err != nil {
			return nil, fmt.Errorf("policy %q: %w", item.ID, err)
		}
		ast, issues := e.env.Compile(item.Condition)
		if issues != nil && issues.Err() != nil {
			return nil, fmt.Errorf("compile policy %q: %w", item.ID, issues.Err())
		}
		if ast.OutputType().String() != "bool" {
			return nil, fmt.Errorf("policy %q condition must return bool", item.ID)
		}
		program, err := e.env.Program(ast, cel.CostLimit(10000), cel.InterruptCheckFrequency(100))
		if err != nil {
			return nil, fmt.Errorf("create policy %q: %w", item.ID, err)
		}
		copy := *item
		copy.Program = program
		copy.Effect = strings.ToLower(item.Effect)
		copy.Actions = append([]string(nil), item.Actions...)
		compiled = append(compiled, &copy)
	}
	return compiled, nil
}

// Evaluate checks all policies against the context
// Returns: allowed (bool), matched (bool), actions ([]string), reason (string)
func (e *Engine) Decide(ctx context.Context, evalCtx *EvalContext) Decision {
	e.mu.RLock()
	defer e.mu.RUnlock()

	decision := Decision{SchemaVersion: "v1", PolicyVersion: e.version, Effect: "block"}
	if evalCtx == nil {
		decision.Reason = "Invalid policy input"
		return decision
	}
	if evalCtx.ValidationError != "" {
		decision.Reason = "Invalid policy input"
		return decision
	}
	if ctx.Err() != nil {
		decision.Reason = "Policy evaluation canceled"
		return decision
	}
	// 1. Get from Pool
	input := e.pool.Get().(map[string]interface{})
	defer func() {
		for _, value := range input {
			clear(value.(map[string]interface{}))
		}
		e.pool.Put(input)
	}()

	// 2. Populate (Safe reuse of maps)
	reqMap := input["request"].(map[string]interface{})
	reqMap["method"] = evalCtx.Request.Method
	reqMap["hostname"] = evalCtx.Request.Hostname
	reqMap["port"] = evalCtx.Request.Port
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
			decision.PolicyID, decision.Matched, decision.Reason = p.ID, true, "Policy evaluation failed: "+p.ID
			return decision
		}

		if matched, ok := out.Value().(bool); ok && matched {
			if strings.EqualFold(p.Effect, "log") {
				logging.Logger.Info("Policy observed", zap.String("id", p.ID))
				continue
			}
			logging.Logger.Debug("Policy Matched", zap.String("id", p.ID), zap.String("effect", p.Effect))

			if strings.EqualFold(p.Effect, "block") {
				return policyDecision(e.version, p, "Blocked by policy "+p.ID)
			}

			return policyDecision(e.version, p, "Allowed by policy "+p.ID)
		}
	}

	// No policy matched -> Default Allow (or should be Block?)
	// Usually proxy is Default Allow unless blocked.
	decision.Reason = "No policy matched"
	if !e.defaultBlock {
		decision.Effect = "allow"
	}
	return decision
}

// Helper to construct context from HTTP Request
func NewEvalContext(req *http.Request, username string, group string) *EvalContext {
	host := req.Host
	authority := req.Host
	if req.URL.IsAbs() {
		authority = req.URL.Host
	}
	destination, parseErr := url.Parse("//" + authority)
	hostname, port := "", 80
	if req.URL.Scheme == "https" || req.Method == http.MethodConnect {
		port = 443
	}
	validationError := ""
	if parseErr != nil || destination.Hostname() == "" || destination.User != nil || destination.Path != "" || destination.RawQuery != "" || destination.Fragment != "" {
		validationError = "invalid destination authority"
	} else {
		hostname = strings.TrimSuffix(strings.ToLower(destination.Hostname()), ".")
		if explicit := destination.Port(); explicit != "" {
			var err error
			port, err = strconv.Atoi(explicit)
			if err != nil || port < 1 || port > 65535 {
				validationError = "invalid destination port"
			}
		}
	}
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
		ValidationError: validationError,
		Client:          ClientInfo{IP: clientIP, Port: clientPort},
		Request: ClientRequest{
			Hostname: hostname,
			Port:     port,
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
	block := effect != "allow"
	if e.defaultBlock != block {
		e.defaultBlock = block
		e.version++
	}
}
