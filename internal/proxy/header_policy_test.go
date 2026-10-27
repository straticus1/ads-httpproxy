package proxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"ads-httpproxy/internal/auth"
	"ads-httpproxy/internal/config"
	"ads-httpproxy/internal/headerpolicy"
	"ads-httpproxy/internal/policy"
	"ads-httpproxy/pkg/logging"
	"github.com/elazarl/goproxy"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

type headerTestAuthenticator struct{}

func (headerTestAuthenticator) Challenge(*http.Request) (string, error) { return "", nil }
func (headerTestAuthenticator) Authenticate(r *http.Request) (bool, string, string, error) {
	auth.BindPrincipal(r, auth.Principal{Subject: "alice", Username: "alice", Issuer: "https://issuer.test"})
	return true, "alice", "", nil
}

func headerTestClient(t *testing.T, s *Server, gateway bool, upstream string) (*http.Client, string) {
	t.Helper()
	var handler http.Handler = s.proxy
	if gateway {
		handler = http.HandlerFunc(s.GatewayHandler)
	}
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	transport := &http.Transport{}
	t.Cleanup(transport.CloseIdleConnections)
	target := server.URL + "/headers"
	if !gateway {
		proxyURL, err := url.Parse(server.URL)
		require.NoError(t, err)
		transport.Proxy = http.ProxyURL(proxyURL)
		target = upstream + "/headers"
	}
	return &http.Client{Transport: transport, Timeout: 5 * time.Second}, target
}

func TestHeaderPolicyWireDefaultsAndIdentity(t *testing.T) {
	logging.Logger = zap.NewNop()
	for _, gateway := range []bool{false, true} {
		for _, identity := range []bool{false, true} {
			name := "forward"
			if gateway {
				name = "gateway"
			}
			if identity {
				name += "-identity"
			}
			t.Run(name, func(t *testing.T) {
				seen := make(chan http.Header, 1)
				upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					seen <- r.Header.Clone()
					w.Header().Set("Via", "1.1 upstream")
					_, _ = io.WriteString(w, "ok")
				}))
				t.Cleanup(upstream.Close)
				cfg := config.NewConfig()
				cfg.Auth.AllowUnauthenticated = true
				cfg.Routes = []config.RouteConfig{{Path: "/", Upstream: upstream.URL}}
				if identity {
					u, err := url.Parse(upstream.URL)
					require.NoError(t, err)
					cfg.Headers = &headerpolicy.Config{IdentityUpstreams: []string{u.Host}}
				}
				s := NewServer(cfg)
				require.NoError(t, s.initErr)
				t.Cleanup(func() { _ = s.Shutdown(context.Background()) })
				s.authenticator = headerTestAuthenticator{}
				client, target := headerTestClient(t, s, gateway, upstream.URL)
				req, err := http.NewRequest("GET", target, nil)
				require.NoError(t, err)
				req.Header["User-Agent"] = []string{""}
				req.Header.Set("Forwarded", "for=203.0.113.8")
				req.Header.Set("X-Forwarded-For", "203.0.113.8")
				req.Header.Set("X-Authenticated-User", "attacker")
				req.Header.Set("Via", "1.0 previous")
				req.Header.Set("Connection", "X-Hop")
				req.Header.Set("X-Hop", "must-not-forward")
				resp, err := client.Do(req)
				require.NoError(t, err)
				defer resp.Body.Close()
				require.Equal(t, http.StatusOK, resp.StatusCode)
				h := <-seen
				require.Empty(t, h.Get("User-Agent"))
				require.Empty(t, h.Get("X-Hop"))
				require.Equal(t, []string{"1.0 previous", "1.1 ads-proxy"}, h.Values("Via"))
				require.Equal(t, []string{"1.1 upstream", "1.1 ads-proxy"}, resp.Header.Values("Via"))
				if gateway {
					require.Contains(t, h.Get("Forwarded"), `for="127.0.0.1"`)
					require.Equal(t, "127.0.0.1", h.Get("X-Forwarded-For"))
					require.Equal(t, "http", h.Get("X-Forwarded-Proto"))
					require.Equal(t, req.URL.Host, h.Get("X-Forwarded-Host"))
				} else {
					require.Empty(t, h.Get("Forwarded"))
					require.Empty(t, h.Get("X-Forwarded-For"))
				}
				if gateway && identity {
					require.Equal(t, "alice", h.Get("X-Authenticated-User"))
				} else {
					require.Empty(t, h.Get("X-Authenticated-User"))
				}
			})
		}
	}
}

func TestHeaderPolicyWireOperationsAfterHooks(t *testing.T) {
	logging.Logger = zap.NewNop()
	for _, gateway := range []bool{false, true} {
		name := "forward"
		if gateway {
			name = "gateway"
		}
		t.Run(name, func(t *testing.T) {
			seen := make(chan http.Header, 1)
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				seen <- r.Header.Clone()
				w.Header().Add("Set-Cookie", "origin=1")
				w.Header().Set("Via", "1.1 origin")
				_, _ = io.WriteString(w, "ok")
			}))
			t.Cleanup(upstream.Close)
			profile := headerpolicy.Profile{
				Request:  headerpolicy.Operations{Set: map[string][]string{"X-Config": {"request"}}, Remove: []string{"X-Config-Remove"}},
				Response: headerpolicy.Operations{Set: map[string][]string{"X-Config": {"response"}}, Remove: []string{"X-Config-Remove"}},
			}
			cfg := config.NewConfig()
			cfg.Auth.AllowUnauthenticated = true
			u, err := url.Parse(upstream.URL)
			require.NoError(t, err)
			cfg.Headers = &headerpolicy.Config{Forward: profile, Gateway: profile, IdentityUpstreams: []string{u.Host}}
			cfg.Routes = []config.RouteConfig{{Path: "/", Upstream: upstream.URL}}
			s := NewServer(cfg)
			require.NoError(t, s.initErr)
			t.Cleanup(func() { _ = s.Shutdown(context.Background()) })
			s.authenticator = headerTestAuthenticator{}
			_, err = s.policyEngine.Replace(s.policyEngine.Snapshot().Version, []*policy.Policy{{ID: "headers", Effect: "allow", Condition: "true", Actions: []string{
				"set_header:X-Cel:https://example.test:8443", "append_header:X-Multi:a", "append_header:X-Multi:b", "remove_header:X-Remove", "append_header:X-Config-Remove:cel",
				"response_set_header:X-Cel:response", "response_append_header:Set-Cookie:policy=2", "response_append_header:Set-Cookie:other=3", "response_remove_header:X-Remove", "response_append_header:X-Config-Remove:cel",
			}}}, "block")
			require.NoError(t, err)
			s.middleware = append(s.middleware, func(req *http.Request, _ *goproxy.ProxyCtx) (*http.Request, *http.Response) {
				// Adaptation hooks can return a fresh request with no private context.
				replacement, err := http.NewRequest(req.Method, req.URL.String(), req.Body)
				if err != nil {
					panic(err)
				}
				replacement.Host = req.Host
				replacement.Header = req.Header.Clone()
				req = replacement
				req.Header.Set("X-Remove", "hook")
				req.Header.Set("X-Config-Remove", "hook")
				req.Header.Set("X-Cel", "hook")
				req.Header.Set("X-Config", "hook")
				return req, nil
			})
			s.respMiddleware = append(s.respMiddleware, func(resp *http.Response, _ *goproxy.ProxyCtx) *http.Response {
				resp.Header.Set("X-Remove", "hook")
				resp.Header.Set("X-Config-Remove", "hook")
				resp.Header.Set("X-Cel", "hook")
				resp.Header.Set("X-Config", "hook")
				resp.Header.Set("Via", "1.1 forged-hook")
				return resp
			})
			client, target := headerTestClient(t, s, gateway, upstream.URL)
			resp, err := client.Get(target)
			require.NoError(t, err)
			defer resp.Body.Close()
			require.Equal(t, http.StatusOK, resp.StatusCode)
			h := <-seen
			require.Equal(t, "request", h.Get("X-Config"))
			require.Equal(t, "https://example.test:8443", h.Get("X-Cel"))
			require.Equal(t, []string{"a", "b"}, h.Values("X-Multi"))
			require.Empty(t, h.Get("X-Remove"))
			require.Empty(t, h.Get("X-Config-Remove"))
			if gateway {
				require.Equal(t, "alice", h.Get("X-Authenticated-User"))
				require.Equal(t, "127.0.0.1", h.Get("X-Forwarded-For"))
			} else {
				require.Empty(t, h.Get("X-Authenticated-User"))
			}
			require.Equal(t, "response", resp.Header.Get("X-Config"))
			require.Equal(t, "response", resp.Header.Get("X-Cel"))
			require.Empty(t, resp.Header.Get("X-Remove"))
			require.Empty(t, resp.Header.Get("X-Config-Remove"))
			require.Equal(t, []string{"origin=1", "policy=2", "other=3"}, resp.Header.Values("Set-Cookie"))
			require.Equal(t, []string{"1.1 origin", "1.1 ads-proxy"}, resp.Header.Values("Via"))
		})
	}
}
