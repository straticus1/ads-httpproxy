package auth

import (
	"encoding/base64"
	"net/http/httptest"
	"testing"

	"ads-httpproxy/internal/config"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestBasicProxyCredentialsAndIsolation(t *testing.T) {
	cfg := &config.AuthConfig{Mechanism: "basic", Users: map[string]string{"alice": "secret:with:colon"}}
	a, err := NewAuthenticator(cfg, zap.NewNop())
	require.NoError(t, err)
	cfg.Users["alice"] = "changed"
	for _, tc := range []struct {
		name, credential string
		valid            bool
	}{{"correct", "alice:secret:with:colon", true}, {"wrong", "alice:wrong", false}, {"unknown", "bob:secret:with:colon", false}, {"malformed", "alice", false}} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "http://upstream.example/", nil)
			r.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(tc.credential)))
			r.Header.Set("Authorization", "Bearer origin-token")
			ok, user, challenge, err := a.Authenticate(r)
			require.NoError(t, err)
			require.Equal(t, tc.valid, ok)
			require.Empty(t, r.Header.Get("Proxy-Authorization"))
			require.Equal(t, "Bearer origin-token", r.Header.Get("Authorization"))
			if tc.valid {
				require.Equal(t, "alice", user)
				p, ok := PrincipalFromContext(r.Context())
				require.True(t, ok)
				require.Equal(t, "local-basic", p.Issuer)
				require.Equal(t, "alice", p.Subject)
				require.Equal(t, []string{"pwd"}, p.AMR)
			} else {
				require.Contains(t, challenge, `Basic realm="ads-proxy"`)
			}
		})
	}
	r := httptest.NewRequest("GET", "http://upstream.example/", nil)
	r.SetBasicAuth("alice", "secret:with:colon")
	ok, _, _, _ := a.Authenticate(r)
	require.False(t, ok, "must not consume origin Authorization")
	require.NotEmpty(t, r.Header.Get("Authorization"))
	r.Header.Add("Proxy-Authorization", "Basic YTpi")
	r.Header.Add("Proxy-Authorization", "Basic YTpi")
	ok, _, _, _ = a.Authenticate(r)
	require.False(t, ok)
}

func TestAuthenticatorMissingUnknownAndBasicValidation(t *testing.T) {
	a, err := NewAuthenticator(nil, zap.NewNop())
	require.NoError(t, err)
	ok, _, _, _ := a.Authenticate(httptest.NewRequest("GET", "http://example.com", nil))
	require.False(t, ok)
	for _, name := range []string{"typo", "BASIC", "None"} {
		cfg := &config.AuthConfig{Mechanism: name, AllowUnauthenticated: true}
		a, err := NewAuthenticator(cfg, zap.NewNop())
		require.Error(t, err)
		require.Nil(t, a)
		require.Error(t, config.ValidateIdentity(cfg))
	}
	for _, users := range []map[string]string{nil, {"": "pass"}, {"user": ""}, {"bad:user": "pass"}} {
		_, err := NewBasicAuthenticator(&config.AuthConfig{Users: users})
		require.Error(t, err)
	}
}
