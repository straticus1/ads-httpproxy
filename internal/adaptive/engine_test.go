package adaptive

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func blockingRule() Rule {
	return Rule{ID: "sensitive", Tenant: "finance", Host: "api.test", PathPrefix: "/upload", Category: "sensitive_data", MinConfidence: 0.8, Action: "block"}
}
func sensitiveInput() Input {
	return Input{Tenant: "finance", Host: "API.TEST", Path: "/upload/file", Category: "sensitive_data", Confidence: 0.9, FindingExpiresAt: time.Now().Add(time.Minute)}
}

func TestObserveShadowEnforceAndFreshness(t *testing.T) {
	for _, mode := range []string{"observe", "shadow", "enforce"} {
		t.Run(mode, func(t *testing.T) {
			e, err := New(Config{Enabled: true, Mode: mode, Rules: []Rule{blockingRule()}})
			require.NoError(t, err)
			d := e.Evaluate(sensitiveInput())
			require.True(t, d.WouldBlock)
			require.Equal(t, mode == "enforce", d.Blocked)
			require.Equal(t, "sensitive", d.RuleID)
			require.EqualValues(t, 1, d.Version)
			for _, change := range []func(*Input){func(i *Input) { i.Tenant = "other" }, func(i *Input) { i.Host = "other.test" }, func(i *Input) { i.Path = "/public" }, func(i *Input) { i.Category = "web" }, func(i *Input) { i.Confidence = 0.2 }, func(i *Input) { i.FindingExpiresAt = time.Now().Add(-time.Second) }, func(i *Input) { i.Confidence = math.NaN() }, func(i *Input) { i.Confidence = math.Inf(1) }} {
				in := sensitiveInput()
				change(&in)
				require.False(t, e.Evaluate(in).WouldBlock)
			}
		})
	}
	r := blockingRule()
	r.ExpiresAt = time.Now().Add(-time.Second)
	e, err := New(Config{Enabled: true, Mode: "enforce", Rules: []Rule{r}})
	require.NoError(t, err)
	require.False(t, e.Evaluate(sensitiveInput()).Blocked)
}

func TestVersionConflictRollbackAndSnapshotIsolation(t *testing.T) {
	e, err := New(Config{Enabled: true, Mode: "shadow", Rules: []Rule{blockingRule()}})
	require.NoError(t, err)
	s := e.Snapshot()
	s.Rules[0].Action = "allow"
	require.Equal(t, "block", e.Snapshot().Rules[0].Action)
	next, err := e.Replace(1, "enforce", []Rule{blockingRule()})
	require.NoError(t, err)
	require.EqualValues(t, 2, next.Version)
	require.True(t, e.Evaluate(sensitiveInput()).Blocked)
	_, err = e.Replace(1, "observe", nil)
	require.ErrorContains(t, err, "conflict")
	require.EqualValues(t, 2, e.Snapshot().Version)
	h := e.History()
	h[0].Rules[0].Action = "allow"
	require.Equal(t, "block", e.History()[0].Rules[0].Action)
	rolled, err := e.Rollback(2, 1)
	require.NoError(t, err)
	require.EqualValues(t, 3, rolled.Version)
	require.Equal(t, "shadow", rolled.Mode)
	require.False(t, e.Evaluate(sensitiveInput()).Blocked)
	_, err = e.Rollback(3, 999)
	require.Error(t, err)
	require.EqualValues(t, 3, e.Snapshot().Version)
}

func TestPolicyPersistenceAndFailedWritePreserveActiveState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "adaptive.json")
	cfg := Config{Enabled: true, Mode: "observe", StateFile: path, Rules: []Rule{blockingRule()}}
	e, err := New(cfg)
	require.NoError(t, err)
	_, err = e.Replace(1, "enforce", []Rule{blockingRule()})
	require.NoError(t, err)
	restarted, err := New(cfg)
	require.NoError(t, err)
	require.Equal(t, e.Snapshot(), restarted.Snapshot())
	require.Equal(t, e.History(), restarted.History())
	require.True(t, restarted.Evaluate(sensitiveInput()).Blocked)
	info, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0600), info.Mode().Perm())
	bad, err := New(Config{Enabled: true, Mode: "shadow", StateFile: filepath.Join(t.TempDir(), "missing", "state")})
	require.NoError(t, err)
	before := bad.Snapshot()
	_, err = bad.Replace(1, "enforce", []Rule{blockingRule()})
	require.Error(t, err)
	require.Equal(t, before, bad.Snapshot())
	require.Empty(t, bad.History())
}

func TestValidationRejectsUnsafePoliciesAndState(t *testing.T) {
	for _, cfg := range []Config{{Mode: "auto"}, {Rules: []Rule{{ID: "bad", Action: "execute"}}}, {Rules: []Rule{{ID: "a", Action: "block"}, {ID: "a", Action: "allow"}}}, {Rules: []Rule{{ID: "a", Action: "block", MinConfidence: math.NaN()}}}, {Rules: []Rule{{ID: "a", Action: "block", MinConfidence: math.Inf(1)}}}, {Rules: []Rule{{ID: "a", Action: "block", Host: "bad/host"}}}} {
		require.Error(t, Validate(cfg))
	}
	for _, value := range []string{"invalid", `{"Current":{"Version":0}}`, strings.Repeat("x", (2<<20)+1)} {
		path := filepath.Join(t.TempDir(), "state")
		require.NoError(t, os.WriteFile(path, []byte(value), 0600))
		_, err := New(Config{StateFile: path})
		require.Error(t, err)
	}
}

func TestHistoryRemainsBoundedAndConcurrentUpdatesConflict(t *testing.T) {
	e, err := New(Config{Enabled: true})
	require.NoError(t, err)
	var successes atomic.Int32
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := e.Replace(1, "shadow", []Rule{blockingRule()}); err == nil {
				successes.Add(1)
			}
		}()
	}
	wg.Wait()
	require.EqualValues(t, 1, successes.Load())
	for range 20 {
		current := e.Snapshot()
		_, err = e.Replace(current.Version, "observe", nil)
		require.NoError(t, err)
	}
	require.Len(t, e.History(), 16)
	_, err = e.Rollback(e.Snapshot().Version, 1)
	require.Error(t, err)
	_, err = json.Marshal(e.History())
	require.NoError(t, err)
}
