package policy

import (
	"context"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"ads-httpproxy/internal/auth"
	"ads-httpproxy/pkg/logging"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestPersistenceMustSucceedBeforePublication(t *testing.T) {
	e, _ := NewEngine()
	failed := errors.New("disk failure")
	version, err := e.ReplaceWithPersist(0, []*Policy{}, "block", func(v uint64) error { require.Equal(t, uint64(1), v); return failed })
	require.ErrorIs(t, err, failed)
	require.Zero(t, version)
	require.Zero(t, e.Snapshot().Version)
	called := false
	version, err = e.ReplaceWithPersist(0, []*Policy{}, "block", func(v uint64) error { called = true; return nil })
	require.NoError(t, err)
	require.True(t, called)
	require.Equal(t, uint64(1), version)
	called = false
	_, err = e.ReplaceWithPersist(0, []*Policy{}, "allow", func(v uint64) error { called = true; return nil })
	require.ErrorIs(t, err, ErrVersionConflict)
	require.False(t, called)
	_, err = e.ReplaceWithPersist(1, []*Policy{{ID: "bad", Effect: "allow", Condition: "1"}}, "allow", func(v uint64) error { called = true; return nil })
	require.Error(t, err)
	require.False(t, called)
	require.Equal(t, "block", e.Snapshot().DefaultEffect)
}

func TestDecisionReplayAndPublicationIsolation(t *testing.T) {
	logging.Logger = zap.NewNop()
	e, err := NewEngine()
	require.NoError(t, err)
	rules := []*Policy{
		{ID: "observe", Effect: "log", Condition: "true"},
		{ID: "first", Effect: "allow", Condition: `request.path == "/public"`, Actions: []string{"redact_headers:X-Secret", "rate_limit:12"}},
		{ID: "deny", Effect: "block", Condition: "true"},
	}
	v, err := e.Replace(0, rules, "block")
	require.NoError(t, err)
	require.Equal(t, uint64(1), v)
	input := &EvalContext{Request: ClientRequest{Path: "/public"}}
	want := e.Decide(context.Background(), input)
	require.Equal(t, "allow", want.Effect)
	require.Equal(t, "first", want.PolicyID)
	require.Equal(t, "v1", want.SchemaVersion)
	require.Equal(t, 12, want.Obligations[1].RequestsPerSecond)
	rules[1].Actions[0] = "launch_shell"
	rules[1].Effect = "block"
	snapshot := e.Snapshot()
	snapshot.Policies[1].Actions[0] = "launch_shell"
	for i := 0; i < 20; i++ {
		require.Equal(t, want, e.Decide(context.Background(), input))
	}
	want.Obligations[0].Headers[0] = "Authorization"
	require.Equal(t, "X-Secret", e.Decide(context.Background(), input).Obligations[0].Headers[0])
	_, err = e.Replace(0, []*Policy{}, "allow")
	require.ErrorIs(t, err, ErrVersionConflict)
	_, err = e.Replace(1, []*Policy{{ID: "broken", Effect: "allow", Condition: "1"}}, "allow")
	require.Error(t, err)
	require.Equal(t, uint64(1), e.Snapshot().Version)
	input.Request.Path = "/private"
	require.Equal(t, "deny", e.Decide(context.Background(), input).PolicyID)
}

func TestDecisionErrorsAndCompetingWriters(t *testing.T) {
	logging.Logger = zap.NewNop()
	e, _ := NewEngine()
	_, err := e.Replace(0, []*Policy{{ID: "error", Effect: "allow", Condition: "user.missing == true"}}, "allow")
	require.NoError(t, err)
	d := e.Decide(context.Background(), &EvalContext{})
	require.Equal(t, "block", d.Effect)
	require.Equal(t, "error", d.PolicyID)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	require.Equal(t, "block", e.Decide(ctx, &EvalContext{}).Effect)
	require.Equal(t, "block", e.Decide(context.Background(), nil).Effect)
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, err := e.Replace(1, []*Policy{}, "block"); results <- err }()
	}
	wg.Wait()
	close(results)
	success, conflict := 0, 0
	for err := range results {
		if err == nil {
			success++
		} else if err == ErrVersionConflict {
			conflict++
		} else {
			t.Fatal(err)
		}
	}
	require.Equal(t, 1, success)
	require.Equal(t, 1, conflict)
	require.Equal(t, uint64(2), e.Decide(context.Background(), &EvalContext{}).PolicyVersion)
}

func TestVerifiedInputIgnoresIdentityHeadersAndNormalizesDestination(t *testing.T) {
	r := httptest.NewRequest("GET", "https://ExAmPle.COM:8443/public", nil)
	r.Host = "spoof.example"
	r.Header.Set("X-Authenticated-User", "attacker")
	now := time.Date(2026, 1, 2, 3, 4, 0, 0, time.UTC)
	input := NewVerifiedInput(r, now)
	require.Empty(t, input.User.Subject)
	require.Equal(t, "example.com", input.Request.Hostname)
	require.Equal(t, 8443, input.Request.Port)
	auth.BindPrincipal(r, auth.Principal{Subject: "verified", Groups: []string{"finance"}})
	input = NewVerifiedInput(r, now)
	require.Equal(t, "verified", input.User.Subject)
	require.Equal(t, 3, input.Time.Hour)
	input.User.Groups[0] = "mutated"
	require.Equal(t, "finance", NewVerifiedInput(r, now).User.Groups[0])
	for _, tc := range []struct {
		method, url string
		port        int
	}{{"GET", "http://example.com/", 80}, {"GET", "https://example.com/", 443}, {"CONNECT", "https://example.com", 443}} {
		req := httptest.NewRequest(tc.method, tc.url, nil)
		require.Equal(t, tc.port, NewVerifiedInput(req, now).Request.Port)
	}
	r.URL.Host = "example.com:70000"
	e, _ := NewEngine()
	require.Equal(t, "block", e.Decide(context.Background(), NewVerifiedInput(r, now)).Effect)
}

func TestPolicyFileBareListAndInvalidReplacement(t *testing.T) {
	e, _ := NewEngine()
	path := filepath.Join(t.TempDir(), "policy.yaml")
	require.NoError(t, os.WriteFile(path, []byte("- id: deny\n  effect: block\n  condition: 'true'\n"), 0600))
	require.NoError(t, e.LoadFromFile(path))
	require.Len(t, e.Snapshot().Policies, 1)
	for _, rules := range [][]*Policy{
		{{ID: "same", Effect: "allow", Condition: "true"}, {ID: "same", Effect: "block", Condition: "true"}},
		{{ID: "header", Effect: "allow", Condition: "true", Actions: []string{"redact_headers:bad(header"}}},
	} {
		_, err := e.Replace(1, rules, "allow")
		require.Error(t, err)
		require.Equal(t, uint64(1), e.Snapshot().Version)
	}
}
