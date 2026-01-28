package auth

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"errors"
	"net/http"
	"net/url"

	"ads-httpproxy/internal/config"

	"github.com/crewjam/saml/samlsp"
	"go.uber.org/zap"
)

type SAMLAuthenticator struct {
	cfg    *config.SAMLConfig
	logger *zap.Logger
	sp     *samlsp.Middleware // Use the middleware helpers from crewjam/saml
}

func NewSAMLAuthenticator(cfg *config.SAMLConfig, logger *zap.Logger) (*SAMLAuthenticator, error) {
	if cfg == nil {
		return nil, errors.New("saml config missing")
	}

	keyPair, err := loadKeyPair(cfg.Cert, cfg.Key)
	if err != nil {
		return nil, err
	}

	idpMetadataURL, err := url.Parse(cfg.MetadataURL)
	if err != nil {
		return nil, err
	}

	rootURL, err := url.Parse(cfg.RootURL)
	if err != nil {
		return nil, err
	}

	// Fetch IdP Metadata
	// Note: In production you might want to cache this or load from file.
	// New function fetches it.
	idpMetadata, err := samlsp.FetchMetadata(context.Background(), http.DefaultClient, *idpMetadataURL)
	if err != nil {
		return nil, err
	}

	sp, err := samlsp.New(samlsp.Options{
		URL:         *rootURL,
		Key:         keyPair.PrivateKey.(*rsa.PrivateKey),
		Certificate: keyPair.Leaf,
		IDPMetadata: idpMetadata,
	})
	if err != nil {
		return nil, err
	}

	return &SAMLAuthenticator{
		cfg:    cfg,
		logger: logger,
		sp:     sp,
	}, nil
}

func loadKeyPair(certPath, keyPath string) (tls.Certificate, error) {
	// Try loading as file paths first
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err == nil {
		return cert, nil
	}

	// If failed, maybe they are raw content?
	// For now, assume paths.
	return tls.Certificate{}, err
}

func (a *SAMLAuthenticator) Challenge(req *http.Request) (string, error) {
	// SAML is browser based. We return a hint.
	// The HTTP layer should handle redirects if possible.
	return "SAML", nil
}

func (a *SAMLAuthenticator) Authenticate(req *http.Request) (bool, string, string, error) {
	// SAML middleware uses a cookie to track session
	// We can check if the session is valid
	session, err := a.sp.Session.GetSession(req)
	if err != nil {
		// Session error or no session
		return false, "", "", nil
	}
	if session != nil {
		// Valid session
		// Get attributes
		if attr, ok := session.(samlsp.SessionWithAttributes); ok {
			attrs := attr.GetAttributes()
			// attrs.Get returns string (the first value)
			// So checking len(val) > 0 is correct
			if uid := attrs.Get("urn:oid:0.9.2342.19200300.100.1.1"); len(uid) > 0 { // uid
				return true, uid, "", nil
			}
			if mail := attrs.Get("urn:oid:0.9.2342.19200300.100.1.3"); len(mail) > 0 { // mail
				return true, mail, "", nil
			}
		}
		// Fallback to NameID?
		// Note: crewjam/saml session object structure depends on implementation.
		// The default JWT session stores Subject in the claims.
		// Let's assume the session implies authentication if GetSession returns non-nil.
		// We might need to introspect better.
		return true, "saml-user", "", nil
	}

	// If not authenticated, we return false.
	// We do NOT return an error unless it's a system error.
	return false, "", "", nil
}

// Handler returns the HTTP handler for SAML endpoints (Metadata, ACS)
func (a *SAMLAuthenticator) Handler() http.Handler {
	return a.sp
}
