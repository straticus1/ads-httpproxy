package mitm

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"time"

	"github.com/elazarl/goproxy"
)

// GenerateCA creates a fresh self-signed CA certificate and key unique to this
// proxy instance. Each instance gets its own CA rather than sharing goproxy's
// well-known built-in CA.
func GenerateCA() (*tls.Certificate, error) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"ADS HTTP Proxy"},
			CommonName:   "ADS Proxy CA",
		},
		NotBefore:             time.Now().Add(-10 * time.Minute),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	if err != nil {
		return nil, err
	}

	leaf, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}

	return &tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  privKey,
		Leaf:        leaf,
	}, nil
}

// LoadCA loads the CA certificate and key from files.
// If files are empty, a unique self-signed CA is generated for this instance.
func LoadCA(certFile, keyFile string) (*tls.Certificate, error) {
	if certFile == "" && keyFile == "" {
		return GenerateCA()
	}
	if certFile == "" || keyFile == "" {
		return nil, fmt.Errorf("CA certificate and key must be provided together")
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}

	// Ensure leaf is parsed
	if cert.Leaf == nil && len(cert.Certificate) > 0 {
		cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return nil, err
		}
	}

	if cert.Leaf == nil || !cert.Leaf.IsCA || cert.Leaf.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, fmt.Errorf("certificate must be a CA with certificate signing usage")
	}
	return &cert, nil
}

// Configure signs per-host certificates with the configured CA.
func Configure(proxy *goproxy.ProxyHttpServer, ca *tls.Certificate) {
	proxy.OnRequest().HandleConnectFunc(func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
		return &goproxy.ConnectAction{Action: goproxy.ConnectMitm, TLSConfig: goproxy.TLSConfigFromCA(ca)}, host
	})
}
