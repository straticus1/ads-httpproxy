package policy

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"ads-httpproxy/internal/auth"
	"ads-httpproxy/internal/headerpolicy"
)

var ErrVersionConflict = errors.New("policy version conflict")

// Decision is the v1 enforcement contract. Only Effect == "allow" permits access.
type Decision struct {
	SchemaVersion string       `json:"schema_version"`
	PolicyVersion uint64       `json:"policy_version"`
	PolicyID      string       `json:"policy_id,omitempty"`
	Effect        string       `json:"effect"`
	Matched       bool         `json:"matched"`
	Reason        string       `json:"reason"`
	Obligations   []Obligation `json:"obligations,omitempty"`
}

type Obligation struct {
	Kind              string   `json:"kind"`
	Headers           []string `json:"headers,omitempty"`
	Name              string   `json:"name,omitempty"`
	Values            []string `json:"values,omitempty"`
	RequestsPerSecond int      `json:"requests_per_second,omitempty"`
}

type Snapshot struct {
	SchemaVersion string    `json:"schema_version"`
	Version       uint64    `json:"version"`
	DefaultEffect string    `json:"default_effect"`
	Policies      []*Policy `json:"policies"`
}

func (e *Engine) Snapshot() Snapshot {
	e.mu.RLock()
	defer e.mu.RUnlock()
	s := Snapshot{SchemaVersion: "v1", Version: e.version, DefaultEffect: "allow", Policies: make([]*Policy, 0, len(e.policies))}
	if e.defaultBlock {
		s.DefaultEffect = "block"
	}
	for _, p := range e.policies {
		copy := *p
		copy.Program = nil
		copy.Actions = append([]string(nil), p.Actions...)
		s.Policies = append(s.Policies, &copy)
	}
	return s
}

// Replace compiles before publishing and checks the version under the publication lock.
// Validation failures and stale writers leave the last-known-good snapshot untouched.
func (e *Engine) Replace(expectedVersion uint64, policies []*Policy, defaultEffect string) (uint64, error) {
	return e.ReplaceWithPersist(expectedVersion, policies, defaultEffect, nil)
}

// ReplaceWithPersist calls persist with the next version under the publication
// lock, after validation and CAS but before swap. persist must not call Engine
// methods. It must return success only after durably writing its transaction.
func (e *Engine) ReplaceWithPersist(expectedVersion uint64, policies []*Policy, defaultEffect string, persist func(uint64) error) (uint64, error) {
	if defaultEffect != "allow" && defaultEffect != "block" {
		return 0, fmt.Errorf("default effect must be allow or block")
	}
	compiled, err := e.compile(policies)
	if err != nil {
		return 0, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.version != expectedVersion {
		return e.version, ErrVersionConflict
	}
	if persist != nil {
		if err := persist(e.version + 1); err != nil {
			return e.version, fmt.Errorf("persist policy: %w", err)
		}
	}
	e.policies, e.defaultBlock = compiled, defaultEffect == "block"
	e.version++
	return e.version, nil
}

func parseObligations(actions []string) ([]Obligation, error) {
	var obligations []Obligation
	for _, action := range actions {
		name, arg, _ := strings.Cut(action, ":")
		o := Obligation{Kind: name}
		switch name {
		case "rate_limit":
			n, err := strconv.Atoi(arg)
			if err != nil || n < 1 || n > 100000 {
				return nil, fmt.Errorf("invalid rate_limit action")
			}
			o.RequestsPerSecond = n
		case "redact_headers":
			for _, h := range strings.Split(arg, ",") {
				h = strings.TrimSpace(h)
				if err := headerpolicy.ValidateOperation(h, nil, true); err != nil {
					return nil, fmt.Errorf("invalid header action: %w", err)
				}
				o.Headers = append(o.Headers, http.CanonicalHeaderKey(h))
			}
		case "set_header", "append_header", "remove_header", "response_set_header", "response_append_header", "response_remove_header":
			remove := strings.HasSuffix(name, "remove_header")
			h := arg
			if !remove {
				var value string
				var found bool
				h, value, found = strings.Cut(arg, ":")
				if !found {
					return nil, fmt.Errorf("header action %q requires a value", name)
				}
				o.Values = []string{value}
			}
			if err := headerpolicy.ValidateOperation(h, o.Values, remove); err != nil {
				return nil, fmt.Errorf("invalid %s action: %w", name, err)
			}
			o.Name = http.CanonicalHeaderKey(h)
			if !remove && !strings.HasPrefix(name, "response_") && o.Name == "Set-Cookie" {
				return nil, fmt.Errorf("Set-Cookie is only supported in response header actions")
			}
		default:
			return nil, fmt.Errorf("unsupported policy action %q", action)
		}
		obligations = append(obligations, o)
	}
	request, response := operationsFromObligations(obligations)
	for _, ops := range []headerpolicy.Operations{request, response} {
		if err := headerpolicy.ApplyOperations(make(http.Header), ops); err != nil {
			return nil, fmt.Errorf("invalid header action collection: %w", err)
		}
	}
	return obligations, nil
}

func policyDecision(version uint64, p *Policy, reason string) Decision {
	obligations, _ := parseObligations(p.Actions) // Validated before publication.
	return Decision{SchemaVersion: "v1", PolicyVersion: version, PolicyID: p.ID, Effect: p.Effect, Matched: true, Reason: reason, Obligations: obligations}
}

// Actions is a compatibility adapter for legacy enforcement code.
func (d Decision) Actions() []string {
	var actions []string
	for _, o := range d.Obligations {
		switch o.Kind {
		case "rate_limit":
			actions = append(actions, "rate_limit:"+strconv.Itoa(o.RequestsPerSecond))
		case "redact_headers":
			actions = append(actions, "redact_headers:"+strings.Join(o.Headers, ","))
		case "remove_header", "response_remove_header":
			actions = append(actions, o.Kind+":"+o.Name)
		case "set_header", "append_header", "response_set_header", "response_append_header":
			for _, value := range o.Values {
				actions = append(actions, o.Kind+":"+o.Name+":"+value)
			}
		}
	}
	return actions
}

func (e *Engine) Evaluate(ctx context.Context, input *EvalContext) (bool, bool, []string, string) {
	d := e.Decide(ctx, input)
	return d.Effect == "allow", d.Matched, d.Actions(), d.Reason
}

// NewVerifiedInput reads identity only from the authenticator's private context key.
// Request headers remain untrusted; now is explicit for deterministic policy replay.
func NewVerifiedInput(r *http.Request, now time.Time) *EvalContext {
	input := NewEvalContext(r, "", "")
	p, _ := auth.PrincipalFromContext(r.Context())
	input.User = UserInfo{Subject: p.Subject, Issuer: p.Issuer, Tenant: p.Tenant, Username: p.Username, Groups: p.Groups, Scopes: p.Scopes, AMR: p.AMR, ACR: p.ACR}
	input.Client.VerifiedMTLS = r.TLS != nil && len(r.TLS.VerifiedChains) > 0 && len(r.TLS.VerifiedChains[0]) > 0
	now = now.UTC()
	input.Time = TimeInfo{Year: now.Year(), Month: int(now.Month()), Day: now.Day(), Hour: now.Hour(), Minute: now.Minute(), DayOfWeek: int(now.Weekday())}
	return input
}
