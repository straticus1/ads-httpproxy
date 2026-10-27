package config

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// IdentityURL permits plaintext only on explicit loopback development endpoints.
func IdentityURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" {
		return nil, fmt.Errorf("identity endpoint must be an absolute HTTPS URL")
	}
	if u.Scheme == "https" {
		return u, nil
	}
	ip := net.ParseIP(u.Hostname())
	if u.Scheme == "http" && (u.Hostname() == "localhost" || ip != nil && ip.IsLoopback()) {
		return u, nil
	}
	return nil, fmt.Errorf("identity endpoint requires HTTPS (HTTP is allowed only on loopback)")
}

func ValidateIdentity(auth *AuthConfig) error {
	if auth == nil {
		return nil
	}
	switch auth.Mechanism {
	case "", "none", "mtls", "ldap", "ad", "ntlm", "kerberos":
	case "basic":
		if len(auth.Users) == 0 {
			return fmt.Errorf("basic auth requires local users")
		}
		for username, password := range auth.Users {
			if strings.TrimSpace(username) == "" || strings.ContainsAny(username, ":\r\n\x00") || password == "" {
				return fmt.Errorf("basic auth requires nonempty usernames/passwords and usernames without colons or controls")
			}
		}
	case "oidc":
		c := auth.OIDC
		if c == nil || c.ClientID == "" {
			return fmt.Errorf("oidc requires issuer and client_id")
		}
		if _, err := IdentityURL(c.Issuer); err != nil {
			return err
		}
		if c.RedirectURL != "" {
			u, err := IdentityURL(c.RedirectURL)
			if err != nil {
				return err
			}
			if u.Path == "" || u.Path == "/" || u.Path == "/auth/login" || u.Path == "/auth/logout" || u.RawQuery != "" {
				return fmt.Errorf("oidc redirect_url requires a dedicated callback path and no query")
			}
		}
		if c.SessionTTLSeconds < 0 || c.SessionTTLSeconds > 86400 || c.SessionCapacity < 0 || c.SessionCapacity > 100000 {
			return fmt.Errorf("oidc session bounds: ttl 0..86400 seconds, capacity 0..100000")
		}
	case "oauth2":
		if auth.OAuth2 == nil {
			return fmt.Errorf("oauth2 config required")
		}
		if _, err := IdentityURL(auth.OAuth2.IntrospectionURL); err != nil {
			return err
		}
	case "saml":
		if auth.SAML == nil {
			return fmt.Errorf("saml config required")
		}
		if _, err := IdentityURL(auth.SAML.MetadataURL); err != nil {
			return err
		}
		u, err := IdentityURL(auth.SAML.RootURL)
		if err != nil {
			return err
		}
		if u.RawQuery != "" || u.Path != "" && u.Path != "/" {
			return fmt.Errorf("saml root_url must be a root origin")
		}
	default:
		return fmt.Errorf("unsupported auth mechanism: %s", auth.Mechanism)
	}
	return nil
}
