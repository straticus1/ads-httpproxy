// Package adaptive applies versioned, explainable rules to fresh classification findings.
package adaptive

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Rule struct {
	ID            string    `json:"id" yaml:"id"`
	Tenant        string    `json:"tenant,omitempty" yaml:"tenant"`
	Host          string    `json:"host,omitempty" yaml:"host"`
	PathPrefix    string    `json:"path_prefix,omitempty" yaml:"path_prefix"`
	Category      string    `json:"category,omitempty" yaml:"category"`
	MinConfidence float64   `json:"min_confidence" yaml:"min_confidence"`
	Action        string    `json:"action" yaml:"action"`
	ExpiresAt     time.Time `json:"expires_at,omitempty" yaml:"expires_at"`
}
type Config struct {
	Enabled   bool   `json:"enabled" yaml:"enabled"`
	Mode      string `json:"mode" yaml:"mode"`
	Rules     []Rule `json:"rules" yaml:"rules"`
	StateFile string `json:"state_file" yaml:"state_file"`
}
type Snapshot struct {
	Version   uint64    `json:"version"`
	Mode      string    `json:"mode"`
	Rules     []Rule    `json:"rules"`
	CreatedAt time.Time `json:"created_at"`
}
type Input struct {
	Tenant           string    `json:"tenant"`
	Host             string    `json:"host"`
	Path             string    `json:"path"`
	Category         string    `json:"category"`
	Confidence       float64   `json:"confidence"`
	FindingExpiresAt time.Time `json:"finding_expires_at"`
}
type Decision struct {
	Version    uint64 `json:"version"`
	Mode       string `json:"mode"`
	Action     string `json:"action"`
	WouldBlock bool   `json:"would_block"`
	Blocked    bool   `json:"blocked"`
	RuleID     string `json:"rule_id,omitempty"`
	Reason     string `json:"reason"`
}
type Engine struct {
	mu      sync.RWMutex
	cfg     Config
	current Snapshot
	history []Snapshot
}

func Validate(c Config) error {
	if c.Mode != "" && c.Mode != "observe" && c.Mode != "shadow" && c.Mode != "enforce" {
		return fmt.Errorf("adaptive mode must be observe, shadow or enforce")
	}
	if len(c.Rules) > 1000 {
		return fmt.Errorf("at most 1000 adaptive rules")
	}
	ids := make(map[string]bool)
	for _, r := range c.Rules {
		if r.ID == "" || ids[r.ID] {
			return fmt.Errorf("adaptive rule IDs must be nonempty and unique")
		}
		ids[r.ID] = true
		if r.Action != "allow" && r.Action != "block" {
			return fmt.Errorf("adaptive action must be allow or block")
		}
		if math.IsNaN(r.MinConfidence) || math.IsInf(r.MinConfidence, 0) || r.MinConfidence < 0 || r.MinConfidence > 1 {
			return fmt.Errorf("confidence must be within 0..1")
		}
		if len(r.Host) > 253 || len(r.PathPrefix) > 4096 || len(r.Tenant) > 256 || len(r.ID) > 128 || len(r.Category) > 128 || strings.ContainsAny(r.Host, "/ \\?\r\n") {
			return fmt.Errorf("invalid adaptive rule match")
		}
	}
	return nil
}
func New(c Config) (*Engine, error) {
	if err := Validate(c); err != nil {
		return nil, err
	}
	if c.Mode == "" {
		c.Mode = "observe"
	}
	e := &Engine{cfg: c, current: Snapshot{Version: 1, Mode: c.Mode, Rules: append([]Rule{}, c.Rules...), CreatedAt: time.Now().UTC()}}
	if c.StateFile != "" {
		data, err := os.ReadFile(c.StateFile)
		if err == nil {
			if len(data) > 2<<20 {
				return nil, fmt.Errorf("adaptive state too large")
			}
			var state struct {
				Current Snapshot
				History []Snapshot
			}
			if json.Unmarshal(data, &state) != nil || state.Current.Version < 1 {
				return nil, fmt.Errorf("invalid adaptive state")
			}
			if err := Validate(Config{Mode: state.Current.Mode, Rules: state.Current.Rules}); err != nil {
				return nil, err
			}
			if len(state.History) > 16 {
				return nil, fmt.Errorf("invalid adaptive history")
			}
			e.current = state.Current
			e.history = state.History
		} else if !os.IsNotExist(err) {
			return nil, err
		}
	}
	return e, nil
}
func clone(s Snapshot) Snapshot      { s.Rules = append([]Rule{}, s.Rules...); return s }
func (e *Engine) Snapshot() Snapshot { e.mu.RLock(); defer e.mu.RUnlock(); return clone(e.current) }
func (e *Engine) History() []Snapshot {
	e.mu.RLock()
	defer e.mu.RUnlock()
	r := make([]Snapshot, len(e.history))
	for i, s := range e.history {
		r[i] = clone(s)
	}
	return r
}
func (e *Engine) publish(expected uint64, mode string, rules []Rule) (Snapshot, error) {
	if expected != e.current.Version {
		return Snapshot{}, fmt.Errorf("policy version conflict")
	}
	c := Config{Mode: mode, Rules: rules}
	if err := Validate(c); err != nil {
		return Snapshot{}, err
	}
	if mode == "" {
		mode = "observe"
	}
	next := Snapshot{Version: e.current.Version + 1, Mode: mode, Rules: append([]Rule{}, rules...), CreatedAt: time.Now().UTC()}
	history := append(append([]Snapshot{}, e.history...), clone(e.current))
	if len(history) > 16 {
		history = history[len(history)-16:]
	}
	if e.cfg.StateFile != "" {
		data, marshalErr := json.Marshal(struct {
			Current Snapshot
			History []Snapshot
		}{next, history})
		if marshalErr != nil {
			return Snapshot{}, marshalErr
		}
		if len(data) > 2<<20 {
			return Snapshot{}, fmt.Errorf("adaptive state exceeds 2 MiB")
		}
		f, err := os.CreateTemp(filepath.Dir(e.cfg.StateFile), ".adaptive-*")
		if err != nil {
			return Snapshot{}, err
		}
		name := f.Name()
		defer os.Remove(name)
		if _, err = f.Write(data); err == nil {
			err = f.Sync()
		}
		closeErr := f.Close()
		if err == nil {
			err = closeErr
		}
		if err == nil {
			err = os.Rename(name, e.cfg.StateFile)
		}
		if err != nil {
			return Snapshot{}, err
		}
	}
	e.history = history
	e.current = next
	return clone(next), nil
}
func (e *Engine) Replace(expected uint64, mode string, rules []Rule) (Snapshot, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.publish(expected, mode, rules)
}
func (e *Engine) Rollback(expected, target uint64) (Snapshot, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, s := range e.history {
		if s.Version == target {
			return e.publish(expected, s.Mode, s.Rules)
		}
	}
	return Snapshot{}, fmt.Errorf("policy version not retained")
}
func (e *Engine) Evaluate(in Input) Decision { return e.EvaluateMany([]Input{in}) }

// EvaluateMany applies rule priority across all fresh evidence, not the order
// findings happened to complete. A later host allow cannot mask an earlier
// classification block merely because the first finding has another category.
func (e *Engine) EvaluateMany(inputs []Input) Decision {
	if e == nil {
		return Decision{Action: "allow", Reason: "adaptive filtering disabled"}
	}
	s := e.Snapshot()
	d := Decision{Version: s.Version, Mode: s.Mode, Action: "allow", Reason: "no adaptive rule matched"}
	for _, r := range s.Rules {
		if !r.ExpiresAt.IsZero() && !r.ExpiresAt.After(time.Now()) {
			continue
		}
		for _, in := range inputs {
			if r.Tenant != "" && r.Tenant != in.Tenant || r.Host != "" && !strings.EqualFold(r.Host, in.Host) || !strings.HasPrefix(in.Path, r.PathPrefix) {
				continue
			}
			if r.Category != "" && (math.IsNaN(in.Confidence) || math.IsInf(in.Confidence, 0) || r.Category != in.Category || !in.FindingExpiresAt.After(time.Now()) || in.Confidence < r.MinConfidence) {
				continue
			}
			d.RuleID = r.ID
			d.Action = r.Action
			d.WouldBlock = r.Action == "block"
			d.Blocked = d.WouldBlock && s.Mode == "enforce"
			d.Reason = "matched adaptive rule " + r.ID
			return d
		}
	}
	return d
}
