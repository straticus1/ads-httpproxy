package analysis

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type analyzerFunc func(context.Context, Event) ([]Finding, error)

func (f analyzerFunc) Analyze(ctx context.Context, e Event) ([]Finding, error) { return f(ctx, e) }
func finding() []Finding {
	return []Finding{{Category: "test", Confidence: 1, Reason: "test classification", ModelVersion: "test-v1"}}
}
func manager(t *testing.T, c Config, a Analyzer) *Manager {
	t.Helper()
	c.Enabled = true
	m, err := New(c, a)
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		require.NoError(t, m.Close(ctx))
	})
	return m
}
func event(id, tenant string) Event {
	return Event{ID: id, Tenant: tenant, URL: "https://example.test/a", Method: "GET", Status: 200}
}

func TestValidateBounds(t *testing.T) {
	require.NoError(t, Validate(Config{}))
	for _, cfg := range []Config{{Workers: -1}, {Workers: 33}, {QueueCapacity: 10001}, {SampleRate: math.NaN()}, {SampleRate: math.Inf(1)}, {SampleRate: 1.1}, {PerTenantPerMinute: -1}, {MaxTenants: 10001}, {MaxBodyBytes: 65537}, {FindingsCapacity: 10001}, {JournalMaxBytes: 1}, {MaxRetries: 4}, {FindingTTLSeconds: -1}} {
		require.Error(t, Validate(cfg))
	}
}

func TestQueueSaturationDoesNotWaitForWorker(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	m := manager(t, Config{Workers: 1, QueueCapacity: 1}, analyzerFunc(func(ctx context.Context, e Event) ([]Finding, error) {
		once.Do(func() { close(started) })
		select {
		case <-release:
			return finding(), nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}))
	require.True(t, m.Submit(event("one", "a")))
	<-started
	require.True(t, m.Submit(event("two", "a")))
	result := make(chan bool, 1)
	go func() { result <- m.Submit(event("three", "a")) }()
	select {
	case accepted := <-result:
		require.False(t, accepted)
	case <-time.After(time.Second):
		t.Fatal("submission waited for worker")
	}
	require.EqualValues(t, 1, m.Stats().DroppedQueue)
	close(release)
	require.NoError(t, m.Close(context.Background()))
	require.EqualValues(t, 2, m.Stats().Completed)
}

func TestTenantBudgetsAndCardinalityAreIsolated(t *testing.T) {
	m := manager(t, Config{PerTenantPerMinute: 1, MaxTenants: 2}, nil)
	require.True(t, m.Submit(event("one", "a")))
	require.False(t, m.Submit(event("two", "a")))
	require.True(t, m.Submit(event("one", "b")))
	require.False(t, m.Submit(event("one", "c")))
	require.NoError(t, m.Close(context.Background()))
	require.Len(t, m.Snapshot(Filter{Tenant: "a"}), 1)
	require.Len(t, m.Snapshot(Filter{Tenant: "b"}), 1)
	require.NotEqual(t, m.Snapshot(Filter{Tenant: "a"})[0].ID, m.Snapshot(Filter{Tenant: "b"})[0].ID)
	require.EqualValues(t, 1, m.Stats().DroppedBudget)
	require.EqualValues(t, 1, m.Stats().DroppedTenant)
}

func TestRetryUsesStableIdentityAndDoesNotDuplicateFindings(t *testing.T) {
	var calls atomic.Int32
	m := manager(t, Config{MaxRetries: 2}, analyzerFunc(func(ctx context.Context, e Event) ([]Finding, error) {
		if calls.Add(1) == 1 {
			return nil, errors.New("temporary")
		}
		return finding(), nil
	}))
	require.True(t, m.Submit(event("same", "a")))
	require.True(t, m.Submit(event("same", "a")))
	require.NoError(t, m.Close(context.Background()))
	require.Len(t, m.Snapshot(Filter{}), 1)
	require.EqualValues(t, 1, m.Stats().Retries)
	require.EqualValues(t, 2, m.Stats().Completed)
}

func TestPrivacyAndPreviewBounds(t *testing.T) {
	seen := make(chan Event, 1)
	m := manager(t, Config{CaptureBodies: true, MaxBodyBytes: 128}, analyzerFunc(func(ctx context.Context, e Event) ([]Finding, error) { seen <- e; return finding(), nil }))
	e := event("privacy", "trusted-tenant")
	e.URL = "https://user:password@example.test/a?token=secret#fragment"
	e.RequestHeaders = http.Header{"Authorization": {"Bearer hidden"}, "Cookie": {"session=hidden"}, "X-Tenant-ID": {"spoof"}, "Content-Type": {"application/json"}}
	e.RequestBody = `{"password":"hidden","access_token":"hidden-token","message":"ok"}`
	e.ResponseHeaders = http.Header{"Content-Type": {"text/plain"}, "Set-Cookie": {"secret=value"}}
	e.ResponseBody = strings.Repeat("a", 256)
	require.True(t, m.Submit(e))
	got := <-seen
	require.NotContains(t, got.URL, "password")
	require.NotContains(t, got.URL, "secret")
	require.NotContains(t, got.URL, "fragment")
	require.Empty(t, got.RequestHeaders.Get("Authorization"))
	require.Empty(t, got.RequestHeaders.Get("X-Tenant-ID"))
	require.Empty(t, got.ResponseHeaders.Get("Set-Cookie"))
	require.NotContains(t, got.RequestBody, "hidden")
	require.Len(t, got.ResponseBody, 128)
	require.Equal(t, "trusted-tenant", got.Tenant)
	require.Equal(t, "Bearer hidden", e.RequestHeaders.Get("Authorization"))
	require.NoError(t, m.Close(context.Background()))
	f := m.Snapshot(Filter{})[0]
	require.Equal(t, "trusted-tenant", f.Tenant)
}

func TestBodyCaptureIsOptInAndBinaryIsExcluded(t *testing.T) {
	for _, cfg := range []Config{{}, {CaptureBodies: true}} {
		seen := make(chan Event, 1)
		m := manager(t, cfg, analyzerFunc(func(ctx context.Context, e Event) ([]Finding, error) { seen <- e; return finding(), nil }))
		e := event("body", "a")
		e.RequestBody = "secret"
		e.RequestHeaders = http.Header{"Content-Type": {"application/octet-stream"}}
		require.True(t, m.Submit(e))
		require.Empty(t, (<-seen).RequestBody)
	}
}

func TestCloseCancelsAnalyzerAtDeadlineAndRejectsSubmissions(t *testing.T) {
	started := make(chan struct{})
	m := manager(t, Config{Workers: 1}, analyzerFunc(func(ctx context.Context, e Event) ([]Finding, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	}))
	require.True(t, m.Submit(event("one", "a")))
	<-started
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	require.ErrorIs(t, m.Close(ctx), context.Canceled)
	require.False(t, m.Submit(event("two", "a")))
	require.NoError(t, m.Close(context.Background()))
	require.EqualValues(t, 1, m.Stats().DroppedClosed)
}

func TestSnapshotIsBoundedCopiedAndExpires(t *testing.T) {
	m := manager(t, Config{Workers: 1, FindingsCapacity: 2}, analyzerFunc(func(context.Context, Event) ([]Finding, error) {
		return []Finding{{Category: "test", Confidence: 1, Reason: "reason", Evidence: map[string]string{"source": "detector"}}}, nil
	}))
	for _, id := range []string{"one", "two", "three"} {
		require.True(t, m.Submit(event(id, "a")))
	}
	require.NoError(t, m.Close(context.Background()))
	snapshot := m.Snapshot(Filter{Limit: 1})
	require.Len(t, snapshot, 1)
	require.Equal(t, "three", snapshot[0].EventID)
	snapshot[0].Evidence["source"] = "changed"
	require.Equal(t, "detector", m.Snapshot(Filter{})[0].Evidence["source"])
	m.findingsMu.Lock()
	m.findings[0].ExpiresAt = time.Now().Add(-time.Second)
	m.findingsMu.Unlock()
	require.Len(t, m.Snapshot(Filter{}), 1)
	require.Len(t, m.Snapshot(Filter{IncludeExpired: true}), 2)
}

func TestJournalPersistsAndRepairsIncompleteTail(t *testing.T) {
	path := filepath.Join(t.TempDir(), "findings.jsonl")
	cfg := Config{Enabled: true, JournalPath: path, JournalMaxBytes: 65536}
	m := manager(t, cfg, nil)
	require.True(t, m.Submit(event("one", "a")))
	require.NoError(t, m.Close(context.Background()))
	original := m.Snapshot(Filter{})
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	require.NoError(t, err)
	_, err = f.WriteString(`{"partial":`)
	require.NoError(t, err)
	require.NoError(t, f.Close())
	restored := manager(t, cfg, nil)
	require.Equal(t, original, restored.Snapshot(Filter{}))
	require.True(t, restored.Submit(event("two", "b")))
	require.NoError(t, restored.Close(context.Background()))
	again := manager(t, cfg, nil)
	require.Len(t, again.Snapshot(Filter{}), 2)
	info, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0600), info.Mode().Perm())
}

func TestJournalRotationAndReplayRemainBounded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "findings.jsonl")
	cfg := Config{Enabled: true, Workers: 1, QueueCapacity: 512, JournalPath: path, JournalMaxBytes: 65536, FindingsCapacity: 5}
	m := manager(t, cfg, analyzerFunc(func(context.Context, Event) ([]Finding, error) {
		return []Finding{{Category: "test", Confidence: 1, Reason: strings.Repeat("r", 1024)}}, nil
	}))
	for i := 0; i < 150; i++ {
		require.True(t, m.Submit(Event{Tenant: "a", URL: "https://example.test"}))
	}
	require.NoError(t, m.Close(context.Background()))
	require.Len(t, m.Snapshot(Filter{}), 5)
	for _, name := range []string{path, path + ".1"} {
		info, err := os.Stat(name)
		require.NoError(t, err)
		require.LessOrEqual(t, info.Size(), int64(65536))
	}
	restored := manager(t, cfg, nil)
	require.Equal(t, m.Snapshot(Filter{}), restored.Snapshot(Filter{}))
}

func TestJournalStartupErrorsAreReturned(t *testing.T) {
	dir := t.TempDir()
	_, err := New(Config{JournalPath: dir}, nil)
	require.Error(t, err)
	path := filepath.Join(dir, "corrupt")
	require.NoError(t, os.WriteFile(path, []byte("not-json\n"), 0600))
	_, err = New(Config{JournalPath: path}, nil)
	require.Error(t, err)
	path = filepath.Join(dir, "oversized")
	require.NoError(t, os.WriteFile(path, []byte(strings.Repeat("x", 65537)), 0600))
	_, err = New(Config{JournalPath: path, JournalMaxBytes: 65536}, nil)
	require.Error(t, err)
}

func TestDefaultClassificationAndNoRawSensitiveEvidence(t *testing.T) {
	e := event("test", "a")
	e.URL = "https://api.openai.com/v1/responses"
	e.RequestBody = "value: 123-45-6789"
	e.Status = 502
	findings, err := (DefaultAnalyzer{}).Analyze(context.Background(), e)
	require.NoError(t, err)
	require.Len(t, findings, 3)
	require.Equal(t, "ai_service", findings[0].Category)
	require.Equal(t, "upstream_error", findings[1].Category)
	require.Equal(t, "sensitive_data", findings[2].Category)
	data, err := json.Marshal(findings)
	require.NoError(t, err)
	require.NotContains(t, string(data), "123-45-6789")
}

func TestConcurrentSubmitAndClose(t *testing.T) {
	m := manager(t, Config{Workers: 4, QueueCapacity: 32}, nil)
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 100 {
				m.Submit(Event{Tenant: "a", URL: "https://example.test"})
			}
		}()
	}
	require.NoError(t, m.Close(context.Background()))
	wg.Wait()
	require.EqualValues(t, 800, m.Stats().Received)
	require.Equal(t, m.Stats().Accepted, m.Stats().Completed)
}

func TestPanickingAndMalformedAnalyzersDoNotKillWorker(t *testing.T) {
	m := manager(t, Config{}, analyzerFunc(func(context.Context, Event) ([]Finding, error) { panic("untrusted analyzer failure") }))
	require.True(t, m.Submit(event("panic", "a")))
	require.NoError(t, m.Close(context.Background()))
	require.EqualValues(t, 1, m.Stats().Errors)
	m = manager(t, Config{}, analyzerFunc(func(context.Context, Event) ([]Finding, error) {
		return []Finding{{Category: "bad", Confidence: math.NaN()}}, nil
	}))
	require.True(t, m.Submit(event("bad", "a")))
	require.NoError(t, m.Close(context.Background()))
	require.Empty(t, m.Snapshot(Filter{}))
	require.EqualValues(t, 1, m.Stats().Errors)
}

func TestSamplingIsDeterministicAndAccounted(t *testing.T) {
	first := manager(t, Config{Workers: 1, QueueCapacity: 256, SampleRate: 0.5}, nil)
	second := manager(t, Config{Workers: 1, QueueCapacity: 256, SampleRate: 0.5}, nil)
	accepted := 0
	for i := 0; i < 200; i++ {
		e := event(strconv.Itoa(i), "a")
		a, b := first.Submit(e), second.Submit(e)
		require.Equal(t, a, b)
		if a {
			accepted++
		}
	}
	require.Greater(t, accepted, 60)
	require.Less(t, accepted, 140)
	require.EqualValues(t, 200-accepted, first.Stats().SampledOut)
	require.NoError(t, first.Close(context.Background()))
	require.NoError(t, second.Close(context.Background()))
}

func TestPolicyDecisionFindingsAndSensitiveEvidence(t *testing.T) {
	m := manager(t, Config{}, nil)
	e := event("block", "trusted")
	e.Decision = "block"
	e.Reason = "policy denied; password=secret"
	e.PolicyVersion = "v2"
	require.True(t, m.Submit(e))
	require.NoError(t, m.Close(context.Background()))
	f := m.Snapshot(Filter{Category: "policy_block"})
	require.Len(t, f, 1)
	require.Equal(t, "v2", f[0].PolicyVersion)
	require.NotContains(t, f[0].Evidence["reason"], "secret")
	m = manager(t, Config{}, analyzerFunc(func(context.Context, Event) ([]Finding, error) {
		return []Finding{{Category: "test", Confidence: 1, Evidence: map[string]string{"access_token": "bare-secret"}}}, nil
	}))
	require.True(t, m.Submit(event("evidence", "a")))
	require.NoError(t, m.Close(context.Background()))
	require.Equal(t, "[REDACTED]", m.Snapshot(Filter{})[0].Evidence["access_token"])
}

func TestIdentityFieldsAreNeverTruncatedIntoAnotherTenant(t *testing.T) {
	m := manager(t, Config{}, nil)
	require.False(t, m.Submit(event("id", strings.Repeat("t", 129))))
	require.EqualValues(t, 1, m.Stats().Errors)
}
