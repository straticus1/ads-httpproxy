package auth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"

	"ads-httpproxy/internal/config"
)

type basicCredential struct {
	username               string
	userHash, passwordHash [32]byte
}

// BasicAuthenticator authenticates forward-proxy credentials only. Origin
// Authorization is never consumed; browser gateway Basic login is not supported.
type BasicAuthenticator struct{ credentials []basicCredential }

func NewBasicAuthenticator(cfg *config.AuthConfig) (*BasicAuthenticator, error) {
	if cfg == nil {
		return nil, fmt.Errorf("basic auth config required")
	}
	validation := *cfg
	validation.Mechanism = "basic"
	if err := config.ValidateIdentity(&validation); err != nil {
		return nil, err
	}
	a := &BasicAuthenticator{}
	for user, password := range cfg.Users {
		a.credentials = append(a.credentials, basicCredential{user, sha256.Sum256([]byte(user)), sha256.Sum256([]byte(password))})
	}
	return a, nil
}

func (*BasicAuthenticator) Challenge(*http.Request) (string, error) {
	return `Basic realm="ads-proxy", charset="UTF-8"`, nil
}

func (a *BasicAuthenticator) Authenticate(r *http.Request) (bool, string, string, error) {
	headers := r.Header.Values("Proxy-Authorization")
	r.Header.Del("Proxy-Authorization")
	challenge, _ := a.Challenge(r)
	if len(headers) != 1 || len(headers[0]) > 8192 {
		return false, "", challenge, nil
	}
	parts := strings.Fields(headers[0])
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Basic") {
		return false, "", challenge, nil
	}
	decoded, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return false, "", challenge, nil
	}
	user, password, ok := strings.Cut(string(decoded), ":")
	if !ok {
		return false, "", challenge, nil
	}
	userHash, passwordHash := sha256.Sum256([]byte(user)), sha256.Sum256([]byte(password))
	matchedUser := ""
	for _, credential := range a.credentials {
		match := subtle.ConstantTimeCompare(userHash[:], credential.userHash[:]) & subtle.ConstantTimeCompare(passwordHash[:], credential.passwordHash[:])
		if match == 1 {
			matchedUser = credential.username
		}
	}
	if matchedUser == "" {
		return false, "", challenge, nil
	}
	BindPrincipal(r, Principal{Subject: matchedUser, Username: matchedUser, Issuer: "local-basic", AuthTime: time.Now(), AMR: []string{"pwd"}})
	return true, matchedUser, "", nil
}
