package pac

import (
	"ads-httpproxy/pkg/logging"
	"go.uber.org/zap"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestGeneratorDoesNotMutateAndEscapesJavaScript(t *testing.T) {
	generator := NewGenerator("proxy.example")
	policy := &Policy{UserID: "user\nalert(1)", BypassDomains: []string{`a";alert(1);//`}, BypassNetworks: []string{"203.0.113.0/27"}}
	result, err := generator.Generate(policy)
	if err != nil {
		t.Fatal(err)
	}
	if policy.ProxyAddr != "" || policy.ProxyPort != 0 {
		t.Fatal("policy mutated")
	}
	if !strings.Contains(result, `a\";alert(1);//`) || strings.Contains(result, "// Generated for: user\nalert") {
		t.Fatal("JavaScript injection")
	}
	if !strings.Contains(result, `"mask":"255.255.255.224"`) || !strings.Contains(result, `PROXY proxy.example:8080`) {
		t.Fatal("incorrect proxy/network output")
	}
	if _, err := generator.Generate(nil); err == nil {
		t.Fatal("nil policy accepted")
	}
}
func TestHandlerUsesCorrectPortAndCopiesPolicies(t *testing.T) {
	logging.Logger = zap.NewNop()
	h := NewHandler(":3128")
	req := httptest.NewRequest("GET", "http://api.example:9090/proxy.pac", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `PROXY api.example:3128`) {
		t.Fatal(w.Body.String())
	}
	policy := &Policy{ProxyAddr: "proxy.example", ProxyPort: 9000, BypassDomains: []string{"one.example"}}
	h.SetUserPolicy("user", policy)
	policy.BypassDomains[0] = "mutated.example"
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := httptest.NewRequest("GET", "http://api.example/proxy.pac?user=user", nil)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if strings.Contains(w.Body.String(), "mutated.example") || !strings.Contains(w.Body.String(), "proxy.example:9000") {
				t.Error("policy alias/port issue")
			}
		}()
	}
	wg.Wait()
}
func TestTenantAndUserPoliciesMerge(t *testing.T) {
	logging.Logger = zap.NewNop()
	h := NewHandler("proxy.example:8080")
	h.SetTenantPolicy("tenant", &Policy{ProxyAddr: "tenant-proxy", BlockAdult: true, BypassDomains: []string{"tenant.example"}})
	h.SetUserPolicy("user", &Policy{BypassDomains: []string{"user.example"}})
	policy := h.getPolicyForUser("user", "tenant")
	if !policy.BlockAdult || policy.ProxyAddr != "tenant-proxy" || len(policy.BypassDomains) != 2 {
		t.Fatalf("policy: %+v", policy)
	}
}
