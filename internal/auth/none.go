package auth

import (
	"fmt"
	"net"
	"net/http"
	"strings"
)

// DenyAllAuthenticator blocks every request. It is the default when
// auth.mechanism = "none" and allow_unauthenticated is not explicitly true.
// This prevents accidental open-relay deployment.
type DenyAllAuthenticator struct{}

func (DenyAllAuthenticator) Challenge(_ *http.Request) (string, error) { return "", nil }

func (DenyAllAuthenticator) Authenticate(_ *http.Request) (bool, string, string, error) {
	return false, "", "", nil
}

// OpenAuthenticator allows requests without credentials. When AllowedNets is
// non-empty only clients from those CIDR ranges are permitted; an empty list
// allows every source IP. Only use on fully trusted, non-public interfaces.
type OpenAuthenticator struct {
	allowedNets []*net.IPNet
}

// NewOpenAuthenticator parses allowedNets CIDRs and returns an OpenAuthenticator.
// Returns an error if any CIDR is malformed.
func NewOpenAuthenticator(allowedNets []string) (*OpenAuthenticator, error) {
	parsed := make([]*net.IPNet, 0, len(allowedNets))
	for _, cidr := range allowedNets {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			continue
		}
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("invalid allowed_source_net %q: %w", cidr, err)
		}
		parsed = append(parsed, ipNet)
	}
	return &OpenAuthenticator{allowedNets: parsed}, nil
}

func (a *OpenAuthenticator) Challenge(_ *http.Request) (string, error) { return "", nil }

func (a *OpenAuthenticator) Authenticate(req *http.Request) (bool, string, string, error) {
	if len(a.allowedNets) == 0 {
		// Explicitly open — no source restriction.
		return true, "anonymous", "", nil
	}

	clientIP := extractClientIP(req.RemoteAddr)
	ip := net.ParseIP(clientIP)
	if ip == nil {
		return false, "", "", nil
	}
	for _, network := range a.allowedNets {
		if network.Contains(ip) {
			return true, "anonymous", "", nil
		}
	}
	return false, "", "", nil
}

// extractClientIP returns just the host portion of a "host:port" address.
func extractClientIP(remoteAddr string) string {
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		return host
	}
	return remoteAddr
}
