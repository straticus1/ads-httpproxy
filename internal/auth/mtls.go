package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"time"
)

// MTLSAuthenticator trusts only certificates verified by the gateway TLS stack.
// Merely presenting a certificate (PeerCertificates) never establishes identity.
type MTLSAuthenticator struct{}

func (MTLSAuthenticator) Challenge(*http.Request) (string, error) { return "", nil }

func (MTLSAuthenticator) Authenticate(r *http.Request) (bool, string, string, error) {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.VerifiedChains[0]) == 0 {
		return false, "", "", nil
	}
	cert := r.TLS.VerifiedChains[0][0]
	now := time.Now()
	if cert == nil || now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
		return false, "", "", nil
	}
	digest := sha256.Sum256(cert.Raw)
	fingerprint := "sha256:" + hex.EncodeToString(digest[:])
	subject := fingerprint
	if len(cert.URIs) > 0 && cert.URIs[0] != nil {
		subject = cert.URIs[0].String()
	}
	username := cert.Subject.CommonName
	if username == "" {
		username = subject
	}
	BindPrincipal(r, Principal{Subject: subject, Username: username,
		Issuer: cert.Issuer.String(), DeviceID: fingerprint, ExpiresAt: cert.NotAfter,
		AMR: []string{"mtls"}})
	// AuthTime is deliberately unset: request time is not TLS handshake time.
	return true, username, "", nil
}
