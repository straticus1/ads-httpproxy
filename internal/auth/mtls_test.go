package auth

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"ads-httpproxy/internal/config"
	"go.uber.org/zap"
)

func TestMTLSRequiresVerifiedCurrentCertificate(t *testing.T) {
	cert := &x509.Certificate{Raw: []byte("signed leaf"), Subject: pkix.Name{CommonName: "workstation"}, Issuer: pkix.Name{CommonName: "trusted CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	a, err := NewAuthenticator(&config.AuthConfig{Mechanism: "mtls"}, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "https://gateway.example/", nil)
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	if ok, _, _, _ := a.Authenticate(r); ok {
		t.Fatal("accepted unverified certificate")
	}
	r.TLS.VerifiedChains = [][]*x509.Certificate{{cert}}
	if ok, user, _, err := a.Authenticate(r); !ok || user != "workstation" || err != nil {
		t.Fatalf("verified auth: %v %s %v", ok, user, err)
	}
	p, ok := PrincipalFromContext(r.Context())
	if !ok || p.Subject != p.DeviceID || len(p.DeviceID) != 71 || p.Issuer != "CN=trusted CA" || !p.ExpiresAt.Equal(cert.NotAfter) || !p.AuthTime.IsZero() {
		t.Fatalf("bad principal: %+v", p)
	}
	uri, _ := url.Parse("spiffe://example/workstation")
	cert.URIs = []*url.URL{uri}
	if ok, _, _, _ := a.Authenticate(r); !ok {
		t.Fatal("URI SAN auth failed")
	}
	p, _ = PrincipalFromContext(r.Context())
	if p.Subject != uri.String() {
		t.Fatal("URI SAN not used")
	}
	cert.NotAfter = time.Now().Add(-time.Minute)
	if ok, _, _, _ := a.Authenticate(r); ok {
		t.Fatal("accepted expired certificate")
	}
	cert.NotAfter = time.Now().Add(time.Hour)
	cert.NotBefore = time.Now().Add(time.Minute)
	if ok, _, _, _ := a.Authenticate(r); ok {
		t.Fatal("accepted not-yet-valid certificate")
	}
}
