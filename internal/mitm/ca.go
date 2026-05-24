package mitm

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
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
	if certFile == "" || keyFile == "" {
		return GenerateCA()
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

	return &cert, nil
}

// fallbackCA returns the built-in goproxy CA as a last resort.
func fallbackCA() *tls.Certificate {
	return &goproxy.GoproxyCa
}

// Configure applies the CA and MITM settings to the proxy
func Configure(proxy *goproxy.ProxyHttpServer, ca *tls.Certificate) {
	proxy.OnRequest().HandleConnect(goproxy.AlwaysMitm)

	// Set the CA for signing
	// goproxy uses a global goproxy.GoproxyCa, but we can override the Action's execution
	// or properly we should set the MItM Connect handlers.
	// Actually goproxy.MitmConnect returns a ConnectAction that does MITM. Only need to set CA if not default.

	// Unfortuantely goproxy global CA is messy.
	// Better approach:

	proxy.OnRequest().HandleConnectFunc(func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
		return &goproxy.ConnectAction{
			Action: goproxy.ConnectMitm,
			TLSConfig: func(host string, ctx *goproxy.ProxyCtx) (*tls.Config, error) {
				return &tls.Config{
					InsecureSkipVerify: true, // For upstream - user might want this configurable
					Certificates:       []tls.Certificate{*ca},
				}, nil
			},
		}, host
	})
}
