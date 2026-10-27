package auth

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Principal is verified identity supplied by an authenticator, never HTTP headers.
type Principal struct {
	Subject   string    `json:"subject"`
	Username  string    `json:"username"`
	Issuer    string    `json:"issuer"`
	Groups    []string  `json:"groups,omitempty"`
	Scopes    []string  `json:"scopes,omitempty"`
	Tenant    string    `json:"tenant,omitempty"`
	DeviceID  string    `json:"device_id,omitempty"`
	AuthTime  time.Time `json:"auth_time,omitempty"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
	AMR       []string  `json:"amr,omitempty"`
	ACR       string    `json:"acr,omitempty"`
}

type principalKey struct{}

func clonePrincipal(p Principal) Principal {
	p.Groups = append([]string(nil), p.Groups...)
	p.Scopes = append([]string(nil), p.Scopes...)
	p.AMR = append([]string(nil), p.AMR...)
	return p
}

func BindPrincipal(r *http.Request, p Principal) {
	*r = *r.WithContext(context.WithValue(r.Context(), principalKey{}, clonePrincipal(p)))
}

func PrincipalFromContext(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(principalKey{}).(Principal)
	if !ok || p.Subject == "" || (!p.ExpiresAt.IsZero() && !time.Now().Before(p.ExpiresAt)) {
		return Principal{}, false
	}
	return clonePrincipal(p), true
}

// BrowserAuthenticator handles only its own explicitly configured gateway host.
type BrowserAuthenticator interface {
	HandleBrowser(http.ResponseWriter, *http.Request) bool
}

func browserHost(r *http.Request, root *url.URL) bool {
	return root != nil && r.Method != http.MethodConnect && !r.URL.IsAbs() && strings.EqualFold(r.Host, root.Host)
}

func localReturnPath(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.IsAbs() || u.Host != "" || !strings.HasPrefix(raw, "/") || strings.HasPrefix(u.Path, "//") || strings.ContainsAny(raw, "\\\r\n") || strings.ContainsAny(u.Path, "\\\r\n") {
		return "/"
	}
	return u.RequestURI()
}

func bearerToken(r *http.Request) string {
	header := r.Header.Get("Proxy-Authorization")
	if header == "" {
		header = r.Header.Get("Authorization")
	}
	parts := strings.Fields(header)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
		return ""
	}
	return parts[1]
}
