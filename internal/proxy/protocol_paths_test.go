package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"ads-httpproxy/internal/auth"
	"ads-httpproxy/internal/config"
	"ads-httpproxy/pkg/logging"
	"github.com/elazarl/goproxy"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestProtocolHTTP2GatewayStreamingCancellation(t *testing.T) {
	logging.Logger = zap.NewNop()
	cancelled := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "data: first\n\n")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
		close(cancelled)
	}))
	defer upstream.Close()
	cfg := config.NewConfig()
	cfg.Auth.AllowUnauthenticated = true
	cfg.Routes = []config.RouteConfig{{Path: "/events", Upstream: upstream.URL}}
	s := NewServer(cfg)
	require.NoError(t, s.initErr)
	defer s.Shutdown(context.Background())
	gateway := httptest.NewUnstartedServer(http.HandlerFunc(s.GatewayHandler))
	gateway.EnableHTTP2 = true
	gateway.StartTLS()
	defer gateway.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", gateway.URL+"/events", nil)
	require.NoError(t, err)
	resp, err := gateway.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, 2, resp.ProtoMajor, "test must negotiate actual HTTP/2")
	line, err := bufio.NewReader(resp.Body).ReadString('\n')
	require.NoError(t, err)
	require.Equal(t, "data: first\n", line)
	cancel()
	resp.Body.Close()
	select {
	case <-cancelled:
	case <-time.After(3 * time.Second):
		t.Fatal("HTTP/2 cancellation did not reach upstream")
	}
}

func TestProtocolConnectDeniedBeforeUpstreamDial(t *testing.T) {
	logging.Logger = zap.NewNop()
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
	defer upstream.Close()
	cfg := config.NewConfig() // Unauthenticated traffic is denied by default.
	s := NewServer(cfg)
	require.NoError(t, s.initErr)
	defer s.Shutdown(context.Background())
	gateway := httptest.NewServer(http.HandlerFunc(s.GatewayHandler))
	defer gateway.Close()
	u, err := url.Parse(gateway.URL)
	require.NoError(t, err)
	conn, err := net.DialTimeout("tcp", u.Host, time.Second)
	require.NoError(t, err)
	defer conn.Close()
	require.NoError(t, conn.SetDeadline(time.Now().Add(3*time.Second)))
	target := strings.TrimPrefix(upstream.URL, "http://")
	_, err = fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	require.NoError(t, err)
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: "CONNECT"})
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusProxyAuthRequired, resp.StatusCode)
	require.Zero(t, calls.Load())
}

func TestProtocolTunnelExpiredIdentityRequiresReconnect(t *testing.T) {
	r := httptest.NewRequest("GET", "https://origin.example/", nil)
	identity := tunnelIdentity{Principal: auth.Principal{Subject: "alice", ExpiresAt: time.Now().Add(-time.Second)}}
	r = r.WithContext(context.WithValue(r.Context(), tunnelIdentityKey{}, identity))
	s := &Server{}
	_, resp := s.middlewareTunnelAuth(r, &goproxy.ProxyCtx{Req: r})
	require.NotNil(t, resp)
	defer resp.Body.Close()
	require.Equal(t, http.StatusProxyAuthRequired, resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Contains(t, string(body), "reconnect")
}

func TestProtocolHTTP2ConnectExplicitlyUnsupported(t *testing.T) {
	logging.Logger = zap.NewNop()
	cfg := config.NewConfig()
	cfg.Auth.AllowUnauthenticated = true
	s := NewServer(cfg)
	require.NoError(t, s.initErr)
	defer s.Shutdown(context.Background())
	gateway := httptest.NewUnstartedServer(http.HandlerFunc(s.GatewayHandler))
	gateway.EnableHTTP2 = true
	gateway.StartTLS()
	defer gateway.Close()
	client := gateway.Client()
	client.Timeout = 3 * time.Second
	req, err := http.NewRequest("CONNECT", gateway.URL, nil)
	require.NoError(t, err)
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, 2, resp.ProtoMajor)
	require.Equal(t, http.StatusNotImplemented, resp.StatusCode)
}

func TestProtocolAuthenticatedCONNECTCarriesIdentityWithoutCredentials(t *testing.T) {
	logging.Logger = zap.NewNop()
	var calls atomic.Int32
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Proxy-Authorization") != "" {
			t.Error("proxy credentials leaked upstream")
		}
		if r.Header.Get("X-Authenticated-User") != "" {
			t.Error("verified identity leaked to forward-proxy origin")
		}
		fmt.Fprint(w, "secure response")
	}))
	defer upstream.Close()
	cfg := config.NewConfig()
	var introspections atomic.Int32
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		introspections.Add(1)
		if r.FormValue("token") != "test-token" {
			http.Error(w, "bad token", 401)
			return
		}
		fmt.Fprintf(w, `{"active":true,"sub":"alice","exp":%d}`, time.Now().Add(time.Hour).Unix())
	}))
	defer idp.Close()
	cfg.Auth = &config.AuthConfig{Mechanism: "oauth2", OAuth2: &config.OAuth2Config{IntrospectionURL: idp.URL, RequireExpiry: true}}
	s := NewServer(cfg)
	require.NoError(t, s.initErr)
	defer s.Shutdown(context.Background())
	s.middleware = append(s.middleware, func(r *http.Request, _ *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		if r.Method != http.MethodConnect {
			p, ok := auth.PrincipalFromContext(r.Context())
			if !ok || p.Subject != "alice" {
				t.Error("verified tunnel principal lost before policy enforcement")
			}
		}
		return r, nil
	})
	roots := x509.NewCertPool()
	roots.AddCert(upstream.Certificate())
	s.proxy.Tr.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	gateway := httptest.NewServer(http.HandlerFunc(s.GatewayHandler))
	defer gateway.Close()
	u, err := url.Parse(gateway.URL)
	require.NoError(t, err)
	// The proxy generates an ephemeral test-only interception CA. Upstream TLS
	// remains verified against the explicit fixture certificate above.
	tr := &http.Transport{Proxy: http.ProxyURL(u), ProxyConnectHeader: http.Header{"Proxy-Authorization": []string{"Bearer test-token"}}, TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	resp, err := client.Get(upstream.URL)
	require.NoError(t, err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, 200, resp.StatusCode)
	require.Equal(t, "secure response", string(body))
	require.EqualValues(t, 1, calls.Load())
	require.EqualValues(t, 1, introspections.Load(), "tunnel must authenticate once, not repeat the outer exchange")
}

func TestProtocolWebSocketGatewayBidirectionalAndClose(t *testing.T) {
	closed := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		defer close(closed)
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		fmt.Fprint(rw, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
		rw.Flush()
		// One masked client text frame, then one unmasked server text frame.
		frame := make([]byte, 8)
		if _, err = io.ReadFull(rw, frame); err != nil {
			return
		}
		if frame[0] != 0x81 || frame[1] != 0x82 {
			return
		}
		payload := []byte{frame[6] ^ frame[2], frame[7] ^ frame[3]}
		if string(payload) != "hi" {
			return
		}
		rw.Write([]byte{0x81, 2, 'o', 'k'})
		rw.Flush()
		io.Copy(io.Discard, rw)
	}))
	defer upstream.Close()
	cfg := config.NewConfig()
	cfg.Routes = []config.RouteConfig{{Path: "/ws", Upstream: upstream.URL}}
	_, _, gateway := platformProxy(t, cfg)
	u, err := url.Parse(gateway)
	require.NoError(t, err)
	conn, err := net.DialTimeout("tcp", u.Host, time.Second)
	require.NoError(t, err)
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	fmt.Fprintf(conn, "GET /ws HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n", u.Host)
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, &http.Request{Method: "GET"})
	require.NoError(t, err)
	require.Equal(t, 101, resp.StatusCode)
	_, err = conn.Write([]byte{0x81, 0x82, 1, 2, 3, 4, 'h' ^ 1, 'i' ^ 2})
	require.NoError(t, err)
	frame := make([]byte, 4)
	_, err = io.ReadFull(reader, frame)
	require.NoError(t, err)
	require.Equal(t, []byte{0x81, 2, 'o', 'k'}, frame)
	conn.Close()
	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		t.Fatal("WebSocket upstream did not close after client disconnect")
	}
}

func protocolRawConnect(t *testing.T, gateway, target, credential string) (net.Conn, *bufio.Reader, *http.Response) {
	t.Helper()
	u, err := url.Parse(gateway)
	require.NoError(t, err)
	conn, err := net.DialTimeout("tcp", u.Host, time.Second)
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
	_, err = fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n%s\r\n", target, target, credential)
	require.NoError(t, err)
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, &http.Request{Method: "CONNECT"})
	require.NoError(t, err)
	return conn, reader, resp
}

func TestProtocolOpaqueCONNECTEchoWithoutCA(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		io.Copy(conn, conn)
	}()
	cfg := config.NewConfig()
	cfg.ConnectMode = "tunnel"
	// Tunnel mode must not load or generate an interception CA. Deliberately
	// invalid paths would fail startup if CA setup were attempted.
	cfg.CaCert = filepath.Join(t.TempDir(), "absent.crt")
	cfg.CaKey = filepath.Join(t.TempDir(), "absent.key")
	_, _, gateway := platformProxy(t, cfg)
	conn, reader, resp := protocolRawConnect(t, gateway, listener.Addr().String(), "")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	payload := []byte{0, 1, 2, 255, 'n', 'o', 't', '-', 'T', 'L', 'S'}
	_, err = conn.Write(payload)
	require.NoError(t, err)
	reply := make([]byte, len(payload))
	_, err = io.ReadFull(reader, reply)
	require.NoError(t, err)
	require.Equal(t, payload, reply)
	conn.Close()
	select {
	case <-finished:
	case <-time.After(3 * time.Second):
		t.Fatal("opaque upstream did not close after client disconnect")
	}
}

func TestProtocolOpaqueCONNECTAuthenticationBeforePolicy(t *testing.T) {
	logging.Logger = zap.NewNop()
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.FormValue("token") != "test-token" {
			http.Error(w, "denied", 401)
			return
		}
		fmt.Fprintf(w, `{"active":true,"sub":"alice","exp":%d}`, time.Now().Add(time.Hour).Unix())
	}))
	defer idp.Close()
	policy := filepath.Join(t.TempDir(), "policy.yaml")
	require.NoError(t, os.WriteFile(policy, []byte("policies:\n  - id: deny-connect\n    effect: block\n    condition: \"request.method == 'CONNECT' && user.subject == 'alice'\"\n"), 0600))
	cfg := config.NewConfig()
	cfg.ConnectMode = "tunnel"
	cfg.PolicyFile = policy
	cfg.Auth = &config.AuthConfig{Mechanism: "oauth2", OAuth2: &config.OAuth2Config{IntrospectionURL: idp.URL, RequireExpiry: true}}
	s := NewServer(cfg)
	require.NoError(t, s.initErr)
	defer s.Shutdown(context.Background())
	gateway := httptest.NewServer(http.HandlerFunc(s.GatewayHandler))
	defer gateway.Close()
	// A real listener detects an accidental dial independently of whether any
	// HTTP request is sent through the opaque tunnel.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	for _, tc := range []struct {
		credential string
		status     int
	}{{"", 407}, {"Proxy-Authorization: Bearer test-token\r\n", 403}} {
		conn, _, resp := protocolRawConnect(t, gateway.URL, listener.Addr().String(), tc.credential)
		require.Equal(t, tc.status, resp.StatusCode)
		resp.Body.Close()
		conn.Close()
	}
	require.NoError(t, listener.(*net.TCPListener).SetDeadline(time.Now().Add(100*time.Millisecond)))
	conn, err := listener.Accept()
	if conn != nil {
		conn.Close()
		t.Fatal("denied CONNECT dialed upstream")
	}
	require.Error(t, err)
	netErr, ok := err.(net.Error)
	require.True(t, ok && netErr.Timeout(), "expected no upstream connection")
}

func TestProtocolCONNECTShutdownClosesBothSockets(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	upstreamEOF := make(chan struct{})
	release := make(chan struct{})
	defer close(release)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		io.Copy(io.Discard, conn)
		close(upstreamEOF)
		// Keep the server socket open after EOF. Shutdown must close the
		// outbound side too instead of waiting for the upstream to close.
		<-release
	}()
	cfg := config.NewConfig()
	cfg.ConnectMode = "tunnel"
	s, _, gateway := platformProxy(t, cfg)
	conn, reader, resp := protocolRawConnect(t, gateway, listener.Addr().String(), "")
	require.Equal(t, 200, resp.StatusCode)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	require.NoError(t, s.Shutdown(ctx))
	_, err = reader.ReadByte()
	require.Error(t, err)
	select {
	case <-upstreamEOF:
	case <-time.After(time.Second):
		t.Fatal("shutdown did not close upstream CONNECT socket")
	}
	conn.Close()
	s.connectSockets.mu.Lock()
	remaining := len(s.connectSockets.connections)
	s.connectSockets.mu.Unlock()
	require.Zero(t, remaining)
	// The test HTTP listener remains live independently of s.httpServer.
	// Admission itself must refuse new CONNECT requests after shutdown.
	_, _, denied := protocolRawConnect(t, gateway, listener.Addr().String(), "")
	defer denied.Body.Close()
	require.Equal(t, 503, denied.StatusCode)
}

func TestProtocolCONNECTShutdownCancelsPendingDial(t *testing.T) {
	started := make(chan struct{})
	s := &Server{proxy: goproxy.NewProxyHttpServer()}
	s.proxy.ConnectDialWithReq = func(req *http.Request, network, addr string) (net.Conn, error) {
		close(started)
		<-req.Context().Done()
		return nil, req.Context().Err()
	}
	s.trackConnectDialer()
	result := make(chan error, 1)
	go func() {
		_, err := s.proxy.ConnectDialWithReq(httptest.NewRequest("CONNECT", "http://origin.test", nil), "tcp", "origin.test:443")
		result <- err
	}()
	<-started
	s.connectSockets.closeAll()
	select {
	case err := <-result:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("shutdown did not cancel pending dial")
	}
	_, err := s.proxy.ConnectDialWithReq(httptest.NewRequest("CONNECT", "http://origin.test", nil), "tcp", "origin.test:443")
	require.ErrorIs(t, err, net.ErrClosed)
}

func TestProtocolCONNECTPreservesTCPHalfClose(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		payload, err := io.ReadAll(conn)
		if err == nil {
			conn.Write(append([]byte("reply:"), payload...))
		}
	}()
	cfg := config.NewConfig()
	cfg.ConnectMode = "tunnel"
	_, _, gateway := platformProxy(t, cfg)
	conn, reader, resp := protocolRawConnect(t, gateway, listener.Addr().String(), "")
	require.Equal(t, 200, resp.StatusCode)
	_, err = conn.Write([]byte("request"))
	require.NoError(t, err)
	require.NoError(t, conn.(*net.TCPConn).CloseWrite())
	reply, err := io.ReadAll(reader)
	require.NoError(t, err)
	require.Equal(t, "reply:request", string(reply))
}

func TestProtocolCONNECTUsesConfiguredParent(t *testing.T) {
	seen := make(chan string, 1)
	parent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "CONNECT" {
			http.Error(w, "CONNECT required", 405)
			return
		}
		want := "Basic " + base64.StdEncoding.EncodeToString([]byte("operator:parent-secret"))
		if r.Header.Get("Proxy-Authorization") != want {
			http.Error(w, "bad credentials", 407)
			return
		}
		seen <- r.Host
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		// Include early tunneled bytes in the same write to exercise preservation
		// of buffered data after the parent CONNECT response headers.
		fmt.Fprint(rw, "HTTP/1.1 200 Connection established\r\n\r\nready")
		rw.Flush()
		io.Copy(conn, rw)
	}))
	defer parent.Close()
	u, err := url.Parse(parent.URL)
	require.NoError(t, err)
	u.User = url.UserPassword("operator", "parent-secret")
	cfg := config.NewConfig()
	cfg.ConnectMode = "tunnel"
	cfg.ParentProxy = u.String()
	_, _, gateway := platformProxy(t, cfg)
	const target = "unresolvable.invalid:443"
	conn, reader, resp := protocolRawConnect(t, gateway, target, "Proxy-Authorization: Bearer caller-must-not-leak\r\n")
	require.Equal(t, 200, resp.StatusCode)
	ready := make([]byte, 5)
	_, err = io.ReadFull(reader, ready)
	require.NoError(t, err)
	require.Equal(t, "ready", string(ready))
	_, err = conn.Write([]byte("echo"))
	require.NoError(t, err)
	reply := make([]byte, 4)
	_, err = io.ReadFull(reader, reply)
	require.NoError(t, err)
	require.Equal(t, "echo", string(reply))
	select {
	case host := <-seen:
		require.Equal(t, target, host)
	case <-time.After(time.Second):
		t.Fatal("configured parent was bypassed")
	}
}

func TestProtocolCONNECTParentRejectsUnsafeConfigurationAndTLS(t *testing.T) {
	logging.Logger = zap.NewNop()
	cfg := config.NewConfig()
	cfg.ConnectMode = "tunnel"
	cfg.ParentProxy = "socks5://127.0.0.1:1080"
	s := NewServer(cfg)
	require.Error(t, s.initErr)
	defer s.Shutdown(context.Background())
	_, err := s.proxy.ConnectDialWithReq(httptest.NewRequest("CONNECT", "http://invalid.test", nil), "tcp", "invalid.test:443")
	require.Error(t, err)
	parent := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("untrusted TLS parent accepted") }))
	defer parent.Close()
	u, err := url.Parse(parent.URL)
	require.NoError(t, err)
	_, err = dialParentCONNECT(context.Background(), u, "tcp", "unresolvable.invalid:443")
	require.Error(t, err)
	oversized := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Oversized", strings.Repeat("x", 70<<10))
		w.WriteHeader(200)
	}))
	defer oversized.Close()
	u, err = url.Parse(oversized.URL)
	require.NoError(t, err)
	_, err = dialParentCONNECT(context.Background(), u, "tcp", "unresolvable.invalid:443")
	require.Error(t, err, "parent response headers must be bounded")
}
