package ai

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"ads-httpproxy/internal/analysis"
	"github.com/stretchr/testify/require"
)

func TestLocalExplanationIsReadOnlyAndUseful(t *testing.T) {
	findings := []analysis.Finding{{ID: "one", Category: "sensitive_data", Evidence: map[string]string{"private": "untouched"}}, {ID: "two", Category: "policy_block"}, {ID: "three", Category: "upstream_error"}}
	before, err := json.Marshal(findings)
	require.NoError(t, err)
	result, err := Explain(context.Background(), Config{Enabled: true}, "Why was this blocked?", findings)
	require.NoError(t, err)
	require.Equal(t, "local", result.Source)
	require.Contains(t, result.Summary, "3 findings")
	require.Len(t, result.Recommendations, 3)
	require.Equal(t, []string{"one", "two", "three"}, result.FindingIDs)
	after, err := json.Marshal(findings)
	require.NoError(t, err)
	require.Equal(t, before, after)
}

func TestProviderReceivesOnlyAllowlistedEvidence(t *testing.T) {
	t.Setenv("TEST_AI_TOKEN", "provider-secret")
	var payload map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "Bearer provider-secret", r.Header.Get("Authorization"))
		require.Equal(t, http.MethodPost, r.Method)
		data, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(data, &payload))
		for _, private := range []string{"private-user", "private-tenant", "private-url", "private-evidence", "private-reason"} {
			require.NotContains(t, string(data), private)
		}
		w.Write([]byte(`{"summary":"Evidence suggests a policy match.","recommendations":["Review the rule in shadow mode."]}`))
	}))
	defer server.Close()
	findings := []analysis.Finding{{ID: "f-1", Tenant: "private-tenant", Subject: "private-user", URL: "https://private-url/", Category: "policy_block", Confidence: 1, ModelVersion: "v1", Reason: "private-reason", Evidence: map[string]string{"value": "private-evidence"}}}
	before, err := json.Marshal(findings)
	require.NoError(t, err)
	result, err := Explain(context.Background(), Config{Enabled: true, ProviderURL: server.URL, Model: "analysis-model", TokenEnv: "TEST_AI_TOKEN"}, "Explain", findings)
	require.NoError(t, err)
	require.Equal(t, "provider", result.Source)
	require.Equal(t, "analysis-model", result.Model)
	require.Equal(t, []string{"f-1"}, result.FindingIDs)
	require.Equal(t, "explain_security_findings", payload["task"])
	require.NotContains(t, payload, "tools")
	require.NotContains(t, payload, "actions")
	after, err := json.Marshal(findings)
	require.NoError(t, err)
	require.Equal(t, before, after)
}

func TestAssistantRejectsInputAndProviderResponseBounds(t *testing.T) {
	_, err := Explain(context.Background(), Config{}, strings.Repeat("q", 4097), nil)
	require.Error(t, err)
	_, err = Explain(context.Background(), Config{}, "", make([]analysis.Finding, 101))
	require.Error(t, err)
	largeSummary, _ := json.Marshal(map[string]any{"summary": strings.Repeat("s", 8193)})
	largeRecommendation, _ := json.Marshal(map[string]any{"summary": "summary", "recommendations": []string{strings.Repeat("r", 2049)}})
	tooMany, _ := json.Marshal(map[string]any{"summary": "summary", "recommendations": make([]string, 21)})
	for _, body := range []string{`not-json`, `{"summary":""}`, `{"summary":"ok"} {}`, `{"summary":"ok","tools":[{"name":"replace_policy"}]}`, strings.Repeat("x", 65537), string(largeSummary), string(largeRecommendation), string(tooMany)} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(body)) }))
		_, err := Explain(context.Background(), Config{ProviderURL: server.URL, Model: "test"}, "", nil)
		require.Error(t, err)
		server.Close()
	}
}

func TestAssistantDoesNotFollowRedirectOrLeakServiceErrors(t *testing.T) {
	var redirected atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { redirected.Store(true) }))
	defer target.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, 307) }))
	defer server.Close()
	cfg := Config{ProviderURL: server.URL, Model: "test"}
	_, err := Explain(context.Background(), cfg, "", nil)
	require.ErrorContains(t, err, "307")
	require.False(t, redirected.Load())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = Explain(ctx, cfg, "", nil)
	require.Error(t, err)
	cfg.TokenEnv = "TEST_AI_TOKEN_ABSENT"
	t.Setenv(cfg.TokenEnv, "")
	_, err = Explain(context.Background(), cfg, "", nil)
	require.ErrorContains(t, err, "credential")
	server2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
		w.Write([]byte("secret-provider-error"))
	}))
	defer server2.Close()
	_, err = Explain(context.Background(), Config{ProviderURL: server2.URL, Model: "test"}, "", nil)
	require.Error(t, err)
	require.NotContains(t, err.Error(), "secret-provider-error")
}

func TestAssistantConfigurationValidation(t *testing.T) {
	for _, cfg := range []Config{{ProviderURL: "https://provider.test"}, {ProviderURL: "http://provider.test", Model: "test"}, {ProviderURL: "https://user:secret@provider.test", Model: "test"}, {TimeoutSeconds: 61}, {TimeoutSeconds: -1}} {
		require.Error(t, Validate(cfg))
	}
}
