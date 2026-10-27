package access

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestVerifiedIdentityRequirements(t *testing.T) {
	cfg := Config{Enabled: true, RequireIdentity: true, RequireMTLS: true, RequiredGroups: []string{"finance"}, RequiredScopes: []string{"payroll:read"}, RequireMFA: true, MaxAuthAgeSeconds: 300}
	e, err := New(cfg)
	require.NoError(t, err)
	id := Identity{Subject: "employee", Issuer: "https://idp.test", VerifiedMTLS: true, Groups: []string{"finance"}, Scopes: []string{"payroll:read"}, AMR: []string{"mfa"}, AuthTime: time.Now()}
	require.NoError(t, e.Check(context.Background(), id))
	for _, tc := range []struct {
		name   string
		change func(*Identity)
	}{
		{"anonymous", func(i *Identity) { i.Subject = "anonymous" }},
		{"unverified certificate", func(i *Identity) { i.VerifiedMTLS = false }},
		{"group", func(i *Identity) { i.Groups = []string{"engineering"} }},
		{"scope", func(i *Identity) { i.Scopes = nil }},
		{"mfa", func(i *Identity) { i.AMR = []string{"pwd"} }},
		{"old auth", func(i *Identity) { i.AuthTime = time.Now().Add(-time.Hour) }},
		{"future auth", func(i *Identity) { i.AuthTime = time.Now().Add(time.Hour) }},
		{"missing auth time", func(i *Identity) { i.AuthTime = time.Time{} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			copy := id
			tc.change(&copy)
			require.Error(t, e.Check(context.Background(), copy))
		})
	}
	var disabled *Evaluator
	require.NoError(t, disabled.Check(context.Background(), Identity{}))
	disabled, err = New(Config{RequireIdentity: true})
	require.NoError(t, err)
	require.NoError(t, disabled.Check(context.Background(), Identity{}))
}

func TestServiceEndpointValidation(t *testing.T) {
	for _, raw := range []string{"https://posture.test/check", "http://127.0.0.1:1234/check", "http://[::1]:1234/check"} {
		require.NoError(t, ValidateEndpoint(raw), raw)
	}
	for _, raw := range []string{"http://posture.test/check", "http://localhost/check", "ftp://posture.test/check", "https://user:pass@posture.test/", "https://posture.test/#fragment", "/relative"} {
		require.Error(t, ValidateEndpoint(raw), raw)
	}
	require.Error(t, Validate(Config{DefaultEffect: "unknown"}))
	require.Error(t, Validate(Config{MaxAuthAgeSeconds: -1}))
}

func TestPostureUsesVerifiedIdentityAndBoundedCache(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "Bearer service-secret", r.Header.Get("Authorization"))
		var sent map[string]any
		require.NoError(t, json.NewDecoder(r.Body).Decode(&sent))
		require.Equal(t, "employee", sent["subject"])
		require.Equal(t, "device-1", sent["device_id"])
		require.NotContains(t, sent, "groups")
		require.NotContains(t, sent, "scopes")
		json.NewEncoder(w).Encode(posture{Compliant: true, ExpiresAt: time.Now().Add(time.Hour)})
	}))
	defer server.Close()
	t.Setenv("TEST_POSTURE_TOKEN", "service-secret")
	e, err := New(Config{Enabled: true, PostureURL: server.URL, PostureTokenEnv: "TEST_POSTURE_TOKEN"})
	require.NoError(t, err)
	id := Identity{Subject: "employee", Issuer: "issuer-1", DeviceID: "device-1", Groups: []string{"private-group"}}
	require.NoError(t, e.Check(context.Background(), id))
	require.NoError(t, e.Check(context.Background(), id))
	require.EqualValues(t, 1, calls.Load())
	id.Issuer = "issuer-2"
	require.NoError(t, e.Check(context.Background(), id))
	require.EqualValues(t, 2, calls.Load())
	e.mu.Lock()
	for k, p := range e.cache {
		require.LessOrEqual(t, time.Until(p.ExpiresAt), time.Minute)
		p.ExpiresAt = time.Now().Add(-time.Second)
		e.cache[k] = p
	}
	e.mu.Unlock()
	require.NoError(t, e.Check(context.Background(), id))
	require.EqualValues(t, 3, calls.Load())
	id.DeviceID = ""
	require.Error(t, e.Check(context.Background(), id))
	require.EqualValues(t, 3, calls.Load())
}

func TestPostureFailureExpiryAndResponseBoundsDeny(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
	}{
		{"noncompliant", `{"compliant":false,"expires_at":"2099-01-01T00:00:00Z"}`, 200},
		{"expired", `{"compliant":true,"expires_at":"2000-01-01T00:00:00Z"}`, 200},
		{"missing expiry", `{"compliant":true}`, 200},
		{"malformed", `not-json`, 200},
		{"oversized", strings.Repeat("x", 16385), 200},
		{"unavailable", `service unavailable`, 503},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(tc.status); w.Write([]byte(tc.body)) }))
			defer server.Close()
			e, err := New(Config{Enabled: true, PostureURL: server.URL})
			require.NoError(t, err)
			require.Error(t, e.Check(context.Background(), Identity{Subject: "user", DeviceID: "device"}))
		})
	}
}

func TestPostureDoesNotFollowRedirectOrIgnoreCancellation(t *testing.T) {
	var redirected atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { redirected.Store(true) }))
	defer target.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer server.Close()
	e, err := New(Config{Enabled: true, PostureURL: server.URL})
	require.NoError(t, err)
	id := Identity{Subject: "user", DeviceID: "device"}
	require.Error(t, e.Check(context.Background(), id))
	require.False(t, redirected.Load())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	require.Error(t, e.Check(ctx, id))
	e, err = New(Config{Enabled: true, PostureURL: server.URL, PostureTokenEnv: "MISSING_TEST_POSTURE_TOKEN"})
	require.NoError(t, err)
	t.Setenv("MISSING_TEST_POSTURE_TOKEN", "")
	require.ErrorContains(t, e.Check(context.Background(), id), "credential")
}
