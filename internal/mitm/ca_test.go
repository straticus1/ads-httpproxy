package mitm

import (
	"crypto/tls"
	"crypto/x509"
	"github.com/elazarl/goproxy"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestMITMUsesConfiguredCAAndHostCertificate(t *testing.T) {
	ca, err := GenerateCA()
	if err != nil {
		t.Fatal(err)
	}
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "intercepted HTTPS") }))
	defer upstream.Close()
	proxy := newTestProxy(ca, upstream.Certificate())
	server := httptest.NewServer(proxy)
	defer server.Close()
	proxyURL, _ := url.Parse(server.URL)
	roots := x509.NewCertPool()
	roots.AddCert(ca.Leaf)
	tr := &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{RootCAs: roots}}
	defer tr.CloseIdleConnections()
	resp, err := (&http.Client{Transport: tr}).Get(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "intercepted HTTPS" {
		t.Fatal(string(body))
	}
	leaf := resp.TLS.PeerCertificates[0]
	if leaf.IsCA {
		t.Fatal("CA itself served as host certificate")
	}
	if err := leaf.CheckSignatureFrom(ca.Leaf); err != nil {
		t.Fatal("host certificate not signed by configured CA", err)
	}
}
func TestGeneratedCAsAreUnique(t *testing.T) {
	first, err := LoadCA("", "")
	if err != nil {
		t.Fatal(err)
	}
	second, err := LoadCA("", "")
	if err != nil {
		t.Fatal(err)
	}
	if first.Leaf.Equal(second.Leaf) {
		t.Fatal("CA reused between instances")
	}
	if _, err := LoadCA("certificate-only", ""); err == nil {
		t.Fatal("incomplete CA pair accepted")
	}
}

func newTestProxy(ca *tls.Certificate, upstream *x509.Certificate) *goproxy.ProxyHttpServer {
	proxy := goproxy.NewProxyHttpServer()
	Configure(proxy, ca)
	roots := x509.NewCertPool()
	roots.AddCert(upstream)
	proxy.Tr.TLSClientConfig = &tls.Config{RootCAs: roots}
	return proxy
}
