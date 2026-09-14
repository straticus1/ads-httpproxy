package examples

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"ads-httpproxy/pkg/plugin"
)

// AuthPlugin demonstrates a configurable proxy authentication hook.
// The proxy's primary authentication policy still applies before this plugin.
type AuthPlugin struct{ Users map[string]string }

func (p *AuthPlugin) Name() string       { return "example-auth" }
func (p *AuthPlugin) APIVersion() string { return plugin.APIVersion }
func (p *AuthPlugin) Version() string    { return "1.0.0" }
func (p *AuthPlugin) Configure(raw json.RawMessage) error {
	var settings struct {
		Users map[string]string `json:"users"`
	}
	if err := json.Unmarshal(raw, &settings); err != nil {
		return err
	}
	if len(settings.Users) == 0 {
		return fmt.Errorf("users must not be empty")
	}
	p.Users = settings.Users
	return nil
}
func (p *AuthPlugin) OnRequest(req *http.Request, _ *plugin.Context) (*http.Request, *http.Response) {
	scheme, encoded, _ := strings.Cut(req.Header.Get("Proxy-Authorization"), " ")
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	user, password, hasPassword := strings.Cut(string(decoded), ":")
	expected, exists := p.Users[user]
	left, right := sha256.Sum256([]byte(password)), sha256.Sum256([]byte(expected))
	if strings.EqualFold(scheme, "Basic") && err == nil && hasPassword && exists && subtle.ConstantTimeCompare(left[:], right[:]) == 1 {
		req.Header.Del("Proxy-Authorization")
		return req, nil
	}
	const message = "Proxy authentication required\n"
	return req, &http.Response{StatusCode: http.StatusProxyAuthRequired, Header: http.Header{"Proxy-Authenticate": []string{`Basic realm="ADS example"`}, "Content-Type": []string{"text/plain"}}, Body: io.NopCloser(strings.NewReader(message)), ContentLength: int64(len(message)), Request: req}
}
func (p *AuthPlugin) OnResponse(resp *http.Response, _ *plugin.Context) *http.Response { return resp }
