package ai

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func gateConfig() EgressConfig {
	return EgressConfig{Enabled: true, Hosts: []string{"approved.test", "blocked.test"}, AllowedHosts: []string{"approved.test"}, AllowedModels: []string{"approved-model"}, RequestsPerMinute: 2}
}
func aiRequest(t *testing.T, target, body string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, target, strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	return req
}

func TestEgressDestinationAndModelRestrictions(t *testing.T) {
	gate, err := NewGate(gateConfig())
	require.NoError(t, err)
	for _, target := range []string{"https://blocked.test/v1", "https://blocked.test:443/v1", "https://blocked.test./v1", "https://BLOCKED.TEST/v1", "http://approved.test/v1", "https://user:secret@approved.test/v1"} {
		req := aiRequest(t, target, `{"model":"approved-model"}`)
		require.Error(t, gate.Check(req, "tenant"), target)
	}
	for _, body := range []string{`{"model":"other-model"}`, `{"stream":true}`, `not-json`} {
		require.Error(t, gate.Check(aiRequest(t, "https://approved.test/v1", body), "tenant"))
	}
	req := aiRequest(t, "https://unrelated.test/", `not-json`)
	req.Header.Set("Authorization", "Bearer unrelated")
	require.NoError(t, gate.Check(req, "tenant"))
	require.Equal(t, "Bearer unrelated", req.Header.Get("Authorization"))
}

func TestEgressRestoresRequestBodyAndReplacesCredentials(t *testing.T) {
	t.Setenv("TEST_AI_UPSTREAM_TOKEN", "managed-token")
	cfg := gateConfig()
	cfg.CredentialEnv = map[string]string{"approved.test": "TEST_AI_UPSTREAM_TOKEN"}
	gate, err := NewGate(cfg)
	require.NoError(t, err)
	body := `{"model":"approved-model","stream":true,"messages":[{"role":"user","content":"hi"}]}`
	req := aiRequest(t, "https://approved.test:443/v1", body)
	for _, header := range []string{"Authorization", "Proxy-Authorization", "Cookie", "X-API-Key", "Api-Key"} {
		req.Header.Set(header, "untrusted-credential")
	}
	require.NoError(t, gate.Check(req, "tenant"))
	require.Equal(t, "Bearer managed-token", req.Header.Get("Authorization"))
	for _, header := range []string{"Proxy-Authorization", "Cookie", "X-API-Key", "Api-Key"} {
		require.Empty(t, req.Header.Get(header))
	}
	data, err := io.ReadAll(req.Body)
	require.NoError(t, err)
	require.Equal(t, body, string(data))
	require.EqualValues(t, len(body), req.ContentLength)
	replay, err := req.GetBody()
	require.NoError(t, err)
	defer replay.Close()
	data, err = io.ReadAll(replay)
	require.NoError(t, err)
	require.Equal(t, body, string(data))
}

func TestEgressBudgetIsTenantIsolatedAndConcurrent(t *testing.T) {
	gate, err := NewGate(gateConfig())
	require.NoError(t, err)
	var allowed atomic.Int32
	var wg sync.WaitGroup
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, err := http.NewRequest("POST", "https://approved.test/v1", strings.NewReader(`{"model":"approved-model"}`))
			if err != nil {
				return
			}
			if gate.Check(req, "one") == nil {
				allowed.Add(1)
			}
		}()
	}
	wg.Wait()
	require.EqualValues(t, 2, allowed.Load())
	require.NoError(t, gate.Check(aiRequest(t, "https://approved.test/v1", `{"model":"approved-model"}`), "two"))
}

type brokenBody struct{ closed bool }

func (b *brokenBody) Read([]byte) (int, error) { return 0, errors.New("sensitive body error") }
func (b *brokenBody) Close() error             { b.closed = true; return nil }

func TestEgressRejectsOversizedBrokenBodiesAndMissingSecrets(t *testing.T) {
	cfg := gateConfig()
	cfg.MaxBodyBytes = 16
	gate, err := NewGate(cfg)
	require.NoError(t, err)
	require.Error(t, gate.Check(aiRequest(t, "https://approved.test/v1", strings.Repeat("x", 17)), "a"))
	req := aiRequest(t, "https://approved.test/v1", "")
	body := &brokenBody{}
	req.Body = body
	err = gate.Check(req, "a")
	require.Error(t, err)
	require.True(t, body.closed)
	require.NotContains(t, err.Error(), "sensitive body error")
	cfg = gateConfig()
	cfg.CredentialEnv = map[string]string{"approved.test": "TEST_AI_ABSENT"}
	t.Setenv("TEST_AI_ABSENT", "")
	gate, err = NewGate(cfg)
	require.NoError(t, err)
	require.ErrorContains(t, gate.Check(aiRequest(t, "https://approved.test/v1", `{"model":"approved-model"}`), "a"), "credential")
}

type gatedTransport struct {
	gate *Gate
	next http.RoundTripper
}

func (tr gatedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := tr.gate.Check(req, "tenant"); err != nil {
		return nil, err
	}
	return tr.next.RoundTrip(req)
}
func TestEgressPreservesLiveSSEDelivery(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		require.Contains(t, string(data), `"stream":true`)
		w.Header().Set("Content-Type", "text/event-stream")
		w.Write([]byte("data: first\n\n"))
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer upstream.Close()
	u, err := url.Parse(upstream.URL)
	require.NoError(t, err)
	cfg := EgressConfig{Enabled: true, Hosts: []string{u.Host}, AllowedHosts: []string{u.Host}, AllowedModels: []string{"approved-model"}}
	gate, err := NewGate(cfg)
	require.NoError(t, err)
	client := upstream.Client()
	client.Transport = gatedTransport{gate: gate, next: client.Transport}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	req := aiRequest(t, upstream.URL, `{"model":"approved-model","stream":true}`)
	req = req.WithContext(ctx)
	response, err := client.Do(req)
	require.NoError(t, err)
	defer response.Body.Close()
	buffer := make([]byte, len("data: first\n\n"))
	_, err = io.ReadFull(response.Body, buffer)
	require.NoError(t, err)
	require.Equal(t, "data: first\n\n", string(buffer))
	require.NoError(t, ctx.Err())
}

func TestEgressValidation(t *testing.T) {
	for _, cfg := range []EgressConfig{{Enabled: true}, {RequestsPerMinute: -1}, {MaxBodyBytes: 5 << 20}, {Hosts: []string{"UPPER.test"}}, {Hosts: []string{"bad/host"}}, {Hosts: []string{"a"}, AllowedHosts: []string{"b"}}, {Hosts: []string{"a"}, AllowedHosts: []string{"a"}, CredentialEnv: map[string]string{"a": ""}}} {
		require.Error(t, ValidateEgress(cfg))
	}
}
