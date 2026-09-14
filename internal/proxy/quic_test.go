package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"ads-httpproxy/internal/auth"
	"ads-httpproxy/internal/config"
	"ads-httpproxy/internal/devtools"
	"ads-httpproxy/pkg/logging"
	"github.com/quic-go/quic-go/http3"
	"go.uber.org/zap"
)

func TestHTTP3GatewayToHTTP3Upstream(t *testing.T) {
	logging.Logger = zap.NewNop()
	// httptest supplies a certificate trusted explicitly by both HTTP/3 clients.
	fixture := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer fixture.Close()
	roots := x509.NewCertPool()
	roots.AddCert(fixture.Certificate())
	upstreamConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstreamConn.Close()
	upstream := &http3.Server{TLSConfig: fixture.TLS.Clone(), Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 3 {
			t.Errorf("upstream protocol: %s", r.Proto)
		}
		w.Header().Set("Content-Type", "text/plain")
		io.WriteString(w, "HTTP/3 upstream")
	})}
	go upstream.Serve(upstreamConn)
	defer upstream.Close()
	target, _ := url.Parse("https://" + upstreamConn.LocalAddr().String())
	open, err := auth.NewOpenAuthenticator(nil)
	if err != nil {
		t.Fatal(err)
	}
	toolkit := devtools.New(&devtools.Config{Enabled: true, CaptureBodies: true})
	s := &Server{cfg: &config.Config{Features: &config.FeatureToggles{ReverseProxy: true}, QUICUpstreams: []string{target.Host}}, authenticator: open, devtools: toolkit, h3Transport: &http3.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}}}
	reverse := httputil.NewSingleHostReverseProxy(target)
	reverse.Transport = s.wrapTransport(nil, false)
	s.compiledRoutes = []PreparedRoute{{Path: "/", Upstream: target, Proxy: reverse}}
	gatewayConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer gatewayConn.Close()
	gateway := &http3.Server{TLSConfig: fixture.TLS.Clone(), Handler: http.HandlerFunc(s.GatewayHandler)}
	s.h3Server = gateway
	s.quicConn = gatewayConn
	go gateway.Serve(gatewayConn)
	clientTransport := &http3.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}}
	defer clientTransport.Close()
	client := &http.Client{Transport: clientTransport, Timeout: 5 * time.Second}
	resp, err := client.Get("https://" + gatewayConn.LocalAddr().String() + "/test")
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if resp.ProtoMajor != 3 || string(body) != "HTTP/3 upstream" {
		t.Fatalf("%s %s", resp.Proto, body)
	}
	entries := toolkit.List()
	if len(entries) != 1 || entries[0].Protocol != "HTTP/3.0" || entries[0].ResponseBody != "HTTP/3 upstream" {
		t.Fatalf("captures: %+v", entries)
	}
	// Verify opaque QUIC datagrams also traverse the fixed-target UDP relay.
	relay, err := NewUDPRelay("127.0.0.1:0", upstreamConn.LocalAddr().String(), 2, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	go relay.Serve(context.Background())
	defer relay.Close()
	relayClientTransport := &http3.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}}
	relayClient := &http.Client{Transport: relayClientTransport, Timeout: 5 * time.Second}
	relayResp, err := relayClient.Get("https://" + relay.Addr().String() + "/opaque")
	if err != nil {
		t.Fatal(err)
	}
	relayBody, err := io.ReadAll(relayResp.Body)
	relayResp.Body.Close()
	relayClientTransport.Close()
	if err != nil || relayResp.ProtoMajor != 3 || string(relayBody) != "HTTP/3 upstream" {
		t.Fatalf("opaque QUIC relay failed: %s %s, %v", relayResp.Proto, relayBody, err)
	}
	// Close the client before graceful shutdown so QUIC connections drain.
	clientTransport.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestQUICTLSConfiguration(t *testing.T) {
	s := &Server{cfg: &config.Config{}}
	if _, err := s.quicTLSConfig(); err == nil {
		t.Fatal("missing TLS accepted")
	}
	fixture := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer fixture.Close()
	dir := t.TempDir()
	certFile := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "key.pem")
	cert := fixture.TLS.Certificates[0]
	key, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0600); err != nil {
		t.Fatal(err)
	}
	s.cfg.QUICCert = certFile
	s.cfg.QUICKey = keyFile
	cfg, err := s.quicTLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Certificates) != 1 || cfg.MinVersion != tls.VersionTLS13 {
		t.Fatal("incorrect TLS configuration")
	}
	s.cfg.QUICKey = "missing"
	if _, err := s.quicTLSConfig(); err == nil {
		t.Fatal("bad key accepted")
	}
}
func TestHTTP3SelectionDoesNotOverrideChains(t *testing.T) {
	s := &Server{cfg: &config.Config{QUICUpstreams: []string{"example.com"}}, h3Transport: &http3.Transport{}}
	next := http.DefaultTransport
	if s.wrapTransport(next, true) != next {
		t.Fatal("HTTP/3 bypassed the configured chain")
	}
	if _, ok := s.wrapTransport(next, false).(*upstreamTransport); !ok {
		t.Fatal("HTTP/3 selection missing")
	}
}
