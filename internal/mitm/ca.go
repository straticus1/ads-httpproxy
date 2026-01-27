package mitm

import (
	"crypto/tls"
	"crypto/x509"

	"github.com/elazarl/goproxy"
)

// LoadCA loads the CA certificate and key from files.
// If files are empty, returns the default goproxy CA.
func LoadCA(certFile, keyFile string) (*tls.Certificate, error) {
	if certFile == "" || keyFile == "" {
		// return default
		return &goproxy.GoproxyCa, nil
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
