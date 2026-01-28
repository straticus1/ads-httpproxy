package auth

import (
	"net/http"
	"net/http/httptest"
	"os"

	"ads-httpproxy/internal/config"

	"github.com/jcmturner/goidentity/v6"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/service"
	"github.com/jcmturner/gokrb5/v8/spnego"
	"go.uber.org/zap"
)

type KerberosAuthenticator struct {
	logger      *zap.Logger
	kt          *keytab.Keytab
	svcSettings *service.Settings
}

func NewKerberosAuthenticator(cfg *config.AuthConfig, logger *zap.Logger) (*KerberosAuthenticator, error) {
	kt, err := keytab.Load(cfg.KRB5Keytab)
	if err != nil {
		if os.IsNotExist(err) {
			logger.Warn("Kerberos keytab not found", zap.String("path", cfg.KRB5Keytab))
			return &KerberosAuthenticator{logger: logger, kt: nil}, nil
		}
		return nil, err
	}

	return &KerberosAuthenticator{
		logger:      logger,
		kt:          kt,
		svcSettings: service.NewSettings(kt),
	}, nil
}

func (a *KerberosAuthenticator) Challenge(req *http.Request) (string, error) {
	// The SPNEGO handler typically adds the WWW-Authenticate header.
	// But since we are calling it inside Authenticate via recorder,
	// we might not use this method directly if we return the recorder's headers.
	// However, to satisfy the interface, we return the standard Negotiation.
	return "Negotiate", nil
}

func (a *KerberosAuthenticator) Authenticate(req *http.Request) (bool, string, string, error) {
	if a.kt == nil {
		return false, "", "", nil
	}

	// We wrap the request and use spnego middleware to validate it.
	// Requires modifying the header to look like Authorziation?
	// gokrb5 logic usually checks Authorization: Negotiate ...
	// Proxy uses Proxy-Authorization. We might need to copy header.

	// Create a dummy handler that signals success
	var user string
	var authenticated bool

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authenticated = true
		creds := goidentity.FromHTTPRequestContext(r)
		if creds != nil {
			user = creds.UserName()
		}
	})

	// Wrap with SPNEGO
	// Note: SPNEGOKRB5Authenticate expects "Authorization", not "Proxy-Authorization".
	// We must temporarily swap headers if needed.

	proxyAuth := req.Header.Get("Proxy-Authorization")
	if proxyAuth != "" {
		req.Header.Set("Authorization", proxyAuth)
		// Defer restore? Actually we are cloning request conceptually or modifying it.
		// Since we return req back, we should probably restore it or be careful.
		defer req.Header.Del("Authorization") // Authorization shouldn't leak upstream if it was proxy auth
	}

	middleware := spnego.SPNEGOKRB5Authenticate(next, a.kt, service.KeytabPrincipal(a.svcSettings.KeytabPrincipal().PrincipalNameString()))

	rec := httptest.NewRecorder()
	middleware.ServeHTTP(rec, req)

	// Check result
	if authenticated {
		return true, user, "", nil
	}

	// If not authenticated, the middleware likely wrote a challenge to the recorder.
	// We need to extract it.
	// The middleware writes 401 Unauthorized. We want 407 Proxy Auth Required.
	// And "WWW-Authenticate". We want "Proxy-Authenticate".

	headers := rec.Header()
	challenge := headers.Get("WWW-Authenticate")

	// If handshake is in progress (e.g. mutual auth output token), it might be in challenge.
	// If the middleware wrote a 401, we consider it a challenge.

	if rec.Code == http.StatusUnauthorized {
		return false, "", challenge, nil
	}

	return false, "", "", nil
}
