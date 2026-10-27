package auth

import (
	"ads-httpproxy/internal/config"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"github.com/crewjam/saml"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"html"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

type fixtureSP struct{ a **SAMLAuthenticator }

func (f fixtureSP) GetServiceProvider(*http.Request, string) (*saml.EntityDescriptor, error) {
	return (*f.a).sp.ServiceProvider.Metadata(), nil
}

type fixtureSAMLSession struct{}

func (fixtureSAMLSession) GetSession(http.ResponseWriter, *http.Request, *saml.IdpAuthnRequest) *saml.Session {
	return &saml.Session{ID: "session-1", NameID: "alice-id", SubjectID: "alice-id", UserName: "alice", Groups: []string{"staff"}, CreateTime: time.Now(), ExpireTime: time.Now().Add(time.Hour)}
}

func TestSAMLMetadataLoginSignedAssertionAndReplay(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fixture"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	dir := t.TempDir()
	certFile := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "key.pem")
	require.NoError(t, os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600))
	require.NoError(t, os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0600))
	var a *SAMLAuthenticator
	idp := &saml.IdentityProvider{Key: key, Certificate: cert, ServiceProviderProvider: fixtureSP{&a}, SessionProvider: fixtureSAMLSession{}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/metadata" {
			idp.ServeMetadata(w, r)
		} else {
			idp.ServeSSO(w, r)
		}
	}))
	defer server.Close()
	metadataURL, _ := url.Parse(server.URL + "/metadata")
	ssoURL, _ := url.Parse(server.URL + "/sso")
	idp.MetadataURL = *metadataURL
	idp.SSOURL = *ssoURL
	a, err = NewSAMLAuthenticator(&config.SAMLConfig{MetadataURL: metadataURL.String(), Cert: certFile, Key: keyFile, RootURL: "https://gateway.test"}, zap.NewNop())
	require.NoError(t, err)
	w := httptest.NewRecorder()
	require.True(t, a.HandleBrowser(w, gatewayRequest("GET", "/saml/metadata")))
	require.Equal(t, 200, w.Code)
	require.Contains(t, w.Body.String(), "AssertionConsumerService")
	w = httptest.NewRecorder()
	require.True(t, a.HandleBrowser(w, gatewayRequest("GET", "/auth/login?return=%2Fapp%3Fa%3D1")))
	require.Equal(t, 302, w.Code)
	trackedCookies := w.Result().Cookies()
	response, err := http.Get(w.Header().Get("Location"))
	require.NoError(t, err)
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	require.NoError(t, err)
	require.Equal(t, 200, response.StatusCode, string(body))
	fields := url.Values{}
	for _, match := range regexp.MustCompile(`name="(SAMLResponse|RelayState)" value="([^"]*)"`).FindAllStringSubmatch(string(body), -1) {
		fields.Set(match[1], html.UnescapeString(match[2]))
	}
	require.NotEmpty(t, fields.Get("SAMLResponse"))
	acs := func(values url.Values) *http.Request {
		r := httptest.NewRequest("POST", "/saml/acs", strings.NewReader(values.Encode()))
		r.Host = "gateway.test"
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		for _, cookie := range trackedCookies {
			r.AddCookie(cookie)
		}
		return r
	}
	bad := url.Values{"SAMLResponse": {base64.StdEncoding.EncodeToString([]byte("invalid"))}, "RelayState": {fields.Get("RelayState")}}
	w = httptest.NewRecorder()
	a.HandleBrowser(w, acs(bad))
	require.Equal(t, 401, w.Code)
	w = httptest.NewRecorder()
	a.HandleBrowser(w, acs(fields))
	require.Equal(t, 302, w.Code, w.Body.String())
	require.Equal(t, "/app?a=1", w.Header().Get("Location"))
	app := gatewayRequest("GET", "/app")
	for _, cookie := range w.Result().Cookies() {
		if cookie.Name == sessionCookie {
			app.AddCookie(cookie)
		}
	}
	ok, user, _, err := a.Authenticate(app)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, "alice", user)
	principal, ok := PrincipalFromContext(app.Context())
	require.True(t, ok)
	require.Equal(t, "alice-id", principal.Subject)
	w = httptest.NewRecorder()
	a.HandleBrowser(w, acs(fields))
	require.Equal(t, 401, w.Code, "assertions must not be replayable even with a copied request-tracker cookie")
	require.Equal(t, 1, a.RevokeSubject(principal.Subject))
	ok, _, _, _ = a.Authenticate(app)
	require.False(t, ok)
	forward := httptest.NewRequest("GET", "https://gateway.test/saml/metadata", nil)
	require.False(t, a.HandleBrowser(httptest.NewRecorder(), forward))
}
