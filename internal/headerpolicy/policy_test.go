package headerpolicy

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func newPolicy(t *testing.T, c *Config) *Policy {
	t.Helper()
	p, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func TestForwardPrivacyAndSnapshot(t *testing.T) {
	p := newPolicy(t, nil)
	r := httptest.NewRequest("GET", "http://origin.test/path", nil)
	r.RemoteAddr = "192.0.2.1:1234"
	r.Header.Set("X-Forwarded-For", "spoof")
	r.Header.Set("X-Authenticated-User", "attacker")
	r.Header.Set("Proxy-Authorization", "secret")
	r.Header.Set("Authorization", "Bearer origin")
	r.Header.Set("Cookie", "session=a")
	r.Header.Set("Via", "1.1 prior")
	s := p.Capture(r, false)
	r.Header.Set("Via", "1.1 forged")
	r.Host = "changed.test"
	if err := p.ApplyRequest(r, &s, "alice", nil); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"Forwarded", "X-Forwarded-For", "X-Authenticated-User", "Proxy-Authorization"} {
		if r.Header.Get(name) != "" {
			t.Errorf("leaked %s", name)
		}
	}
	if r.Header.Get("Authorization") != "Bearer origin" || r.Header.Get("Cookie") != "session=a" {
		t.Fatal("origin credentials removed")
	}
	if !reflect.DeepEqual(r.Header.Values("Via"), []string{"1.1 prior", "1.1 ads-proxy"}) {
		t.Fatal(r.Header)
	}
	if v, ok := r.Header["User-Agent"]; !ok || len(v) != 1 || v[0] != "" {
		t.Fatal("Go default UA not suppressed")
	}
}
func TestGatewayTrustAndIPv6(t *testing.T) {
	for _, tc := range []struct {
		peer    string
		trusted bool
		want    string
	}{{"192.0.2.1:123", true, "192.0.2.1"}, {"198.51.100.1:123", false, "198.51.100.1"}, {"[2001:db8::1]:123", true, "[2001:db8::1]"}} {
		t.Run(tc.peer, func(t *testing.T) {
			p := newPolicy(t, &Config{TrustedProxies: []string{"192.0.2.0/24", "2001:db8::/32"}})
			r := httptest.NewRequest("GET", "https://ingress.test/path", nil)
			r.RemoteAddr = tc.peer
			r.Header.Set("Forwarded", "for=203.0.113.1;proto=https")
			r.Header.Set("X-Forwarded-For", "203.0.113.1")
			s := p.Capture(r, true)
			r.Host = "changed"
			r.RemoteAddr = "127.0.0.1:1"
			r.Header.Set("Forwarded", "for=evil")
			if err := p.ApplyRequest(r, &s, "alice", nil); err != nil {
				t.Fatal(err)
			}
			got := r.Header.Get("Forwarded")
			if strings.Contains(got, "203.0.113.1") != tc.trusted || !strings.Contains(got, "for=\""+tc.want+"\"") || !strings.Contains(got, "host=\"ingress.test\"") {
				t.Fatal(got)
			}
			if r.Header.Get("X-Forwarded-Proto") != "https" {
				t.Fatal(r.Header)
			}
		})
	}
}
func TestIdentityOptInEffectiveUpstream(t *testing.T) {
	p := newPolicy(t, &Config{IdentityUpstreams: []string{"upstream.test:443"}})
	for _, tc := range []struct {
		gateway  bool
		upstream string
		want     bool
	}{{true, "upstream.test:443", true}, {false, "upstream.test:443", false}, {true, "upstream.test", false}, {true, "evil.test:443", false}} {
		r := httptest.NewRequest("GET", "https://ingress.test", nil)
		s := p.Capture(r, tc.gateway)
		r.URL.Host = tc.upstream
		r.Host = "upstream.test:443"
		if err := p.ApplyRequest(r, &s, "alice", nil); err != nil {
			t.Fatal(err)
		}
		if (r.Header.Get("X-Authenticated-User") == "alice") != tc.want {
			t.Fatal(tc, r.Header)
		}
	}
}
func TestOperationsAndTerminalRemoval(t *testing.T) {
	p := newPolicy(t, &Config{Forward: Profile{Request: Operations{Set: map[string][]string{"X-Values": {"a", "b"}}, Remove: []string{"X-Secret"}}, Response: Operations{Append: map[string][]string{"Set-Cookie": {"c=3"}}}}})
	r := httptest.NewRequest("GET", "http://origin.test", nil)
	s := p.Capture(r, false)
	if err := p.ApplyRequest(r, &s, "", []string{"Cookie"}, Operations{Append: map[string][]string{"X-Values": {"c"}}, Set: map[string][]string{"X-Secret": {"leak"}}}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(r.Header.Values("X-Values"), []string{"a", "b", "c"}) || r.Header.Get("X-Secret") != "" {
		t.Fatal(r.Header)
	}
	resp := &http.Response{StatusCode: 200, ProtoMajor: 2, Header: http.Header{"Set-Cookie": {"a=1", "b=2"}, "Via": {"1.1 forged"}, "X-Authenticated-User": {"leak"}}}
	if err := p.ApplyResponse(resp, &s, []string{"1.1 origin"}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(resp.Header.Values("Set-Cookie"), []string{"a=1", "b=2", "c=3"}) || !reflect.DeepEqual(resp.Header.Values("Via"), []string{"1.1 origin", "2.0 ads-proxy"}) || resp.Header.Get("X-Authenticated-User") != "" {
		t.Fatal(resp.Header)
	}
}
func TestProtectedAndValidation(t *testing.T) {
	for _, name := range []string{"Host", "Content-Length", "Connection", "Transfer-Encoding", "Via", "Forwarded", "X-Forwarded-For", "X-Authenticated-User", "Proxy-Authorization"} {
		for _, remove := range []bool{false, true} {
			if err := ValidateOperation(name, []string{"x"}, remove); err == nil {
				t.Errorf("accepted %s remove=%v", name, remove)
			}
		}
	}
	for _, name := range []string{"Authorization", "Cookie"} {
		if ValidateOperation(name, []string{"x"}, false) == nil || ValidateOperation(name, nil, true) != nil {
			t.Fatal(name)
		}
	}
	for _, value := range []string{"a\r\nb", "a\x00b", "a\tb", strings.Repeat("a", maxBytes+1)} {
		if ValidateOperation("X-Test", []string{value}, false) == nil {
			t.Fatal("accepted invalid value")
		}
	}
	for _, c := range []*Config{{Forward: Profile{Forwarded: "bad"}}, {TrustedProxies: []string{"127.0.0.1"}}, {ViaPseudonym: "bad token"}, {IdentityUpstreams: []string{"*.test"}}, {Forward: Profile{Request: Operations{Set: map[string][]string{"X-Test": {"a"}, "x-test": {"b"}}}}}} {
		if Validate(c) == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	h := http.Header{"X-Test": {"original"}}
	if err := ApplyOperations(h, Operations{Set: map[string][]string{"X-Test": {"new"}, "Z-Bad": {"bad\n"}}}); err == nil || h.Get("X-Test") != "original" {
		t.Fatal("non atomic validation")
	}
}
func TestConnectionNomineesAndWebsocket(t *testing.T) {
	for _, upgrade := range []bool{false, true} {
		r := httptest.NewRequest("GET", "http://origin.test", nil)
		r.Header.Set("Connection", "X-Secret, Upgrade")
		r.Header.Set("X-Secret", "secret")
		if upgrade {
			r.Header.Set("Upgrade", "websocket")
		}
		p := newPolicy(t, nil)
		s := p.Capture(r, false)
		if err := p.ApplyRequest(r, &s, "", nil); err != nil {
			t.Fatal(err)
		}
		if r.Header.Get("X-Secret") != "" || (r.Header.Get("Upgrade") == "websocket") != upgrade {
			t.Fatal(r.Header)
		}
		resp := &http.Response{StatusCode: 101, ProtoMajor: 1, ProtoMinor: 1, Header: http.Header{"Connection": {"Upgrade, X-Secret"}, "Upgrade": {"websocket"}, "X-Secret": {"secret"}}}
		if err := p.ApplyResponse(resp, &s, nil); err != nil {
			t.Fatal(err)
		}
		if resp.Header.Get("X-Secret") != "" || (resp.Header.Get("Upgrade") == "websocket") != upgrade {
			t.Fatal(resp.Header)
		}
	}
}
func TestInvalidTrustedChainsAreDiscarded(t *testing.T) {
	p := newPolicy(t, &Config{TrustedProxies: []string{"192.0.2.0/24"}})
	r := httptest.NewRequest("GET", "http://origin.test", nil)
	r.RemoteAddr = "192.0.2.1:1"
	r.Header.Set("Forwarded", "for=good;broken")
	r.Header.Set("X-Forwarded-For", "not-an-ip")
	r.Header.Set("Via", "bad\r\nvalue")
	s := p.Capture(r, true)
	if err := p.ApplyRequest(r, &s, "", nil); err != nil {
		t.Fatal(err)
	}
	if r.Header.Get("X-Forwarded-For") != "192.0.2.1" || strings.Contains(r.Header.Get("Forwarded"), "broken") || !reflect.DeepEqual(r.Header.Values("Via"), []string{"1.1 ads-proxy"}) {
		t.Fatal(r.Header)
	}
}
func TestConfigIsCopied(t *testing.T) {
	c := &Config{Forward: Profile{Request: Operations{Set: map[string][]string{"X-Test": {"before"}}}}}
	p := newPolicy(t, c)
	c.Forward.Request.Set["X-Test"][0] = "after"
	r := httptest.NewRequest("GET", "http://origin.test", nil)
	s := p.Capture(r, false)
	if err := p.ApplyRequest(r, &s, "", nil); err != nil {
		t.Fatal(err)
	}
	if r.Header.Get("X-Test") != "before" {
		t.Fatal(r.Header)
	}
}

func TestViaProtocolTokensAndComments(t *testing.T) {
	for _, value := range []string{"1.1 edge", "HTTP/1.1 edge:8080", "http/2 gateway", "HTTP/3 edge", "other/v7 bridge", "1.1 [2001:db8::1]:80", "1.1 edge (comment, nested (value) and \\) quote), 2 next"} {
		if got := safeVia([]string{value}); !reflect.DeepEqual(got, []string{value}) {
			t.Errorf("discarded valid Via %q", value)
		}
	}
	for _, value := range []string{"1.1 edge (unterminated", "1.1 edge (closed) trailing", "1.1 edge) malformed", "HTTP//1.1 edge", "/1.1 edge", "1.1 edge(comment)", "1.1 edge (one) (two)", "1.1 edge,", "1.1 edge (" + strings.Repeat("(", 9) + ")"} {
		if safeVia([]string{value}) != nil {
			t.Errorf("accepted malformed Via %q", value)
		}
	}
}

func TestCapturedConnectionNomineesSurviveEarlierCleanup(t *testing.T) {
	p := newPolicy(t, nil)
	r := httptest.NewRequest("GET", "http://origin.test", nil)
	r.Header.Set("Connection", "X-Private, Authorization")
	r.Header.Set("X-Private", "secret")
	r.Header.Set("Authorization", "Bearer nominated-hop-credential")
	s := p.Capture(r, false)
	// goproxy removes Connection before invoking its configured RoundTripper.
	r.Header.Del("Connection")
	if err := p.ApplyRequest(r, &s, "", nil); err != nil {
		t.Fatal(err)
	}
	if r.Header.Get("X-Private") != "" || r.Header.Get("Authorization") != "" {
		t.Fatal("hop nominees leaked", r.Header)
	}
}
