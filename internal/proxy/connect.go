package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"ads-httpproxy/internal/auth"
	"ads-httpproxy/internal/cache"
	"github.com/elazarl/goproxy"
)

type tunnelIdentityKey struct{}
type tunnelIdentity struct {
	Principal auth.Principal
	TLS       *tls.ConnectionState
}

// middlewareTunnelAuth accepts only an identity verified before this tunnel was
// established. Credentials are not replayed from client-controlled inner headers.
func (s *Server) middlewareTunnelAuth(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	identity, ok := req.Context().Value(tunnelIdentityKey{}).(tunnelIdentity)
	if !ok {
		return s.middlewareAuth(req, ctx)
	}
	auth.BindPrincipal(req, identity.Principal)
	p, valid := auth.PrincipalFromContext(req.Context())
	if !valid {
		return req, goproxy.NewResponse(req, "text/plain", http.StatusProxyAuthRequired, "Tunnel identity expired; reconnect")
	}
	for _, h := range []string{"X-Authenticated-User", "X-Tenant-ID", "X-Device-ID", "X-Device-Compliant", "X-Authenticated-Groups", "X-Authenticated-Scopes", "X-Authenticated-Tenant", "X-Groups", "Proxy-Authorization"} {
		req.Header.Del(h)
	}
	if p.Subject != "anonymous" || p.Issuer != "local" {
		cache.MarkPrivate(req)
	}
	stripIdentityCookies(req)
	req.Header.Set("X-Authenticated-User", p.Username)
	return req, nil
}

func (s *Server) handleConnectRequest(w http.ResponseWriter, r *http.Request) {
	if s.connectSockets.isClosed() {
		http.Error(w, "Proxy shutting down", http.StatusServiceUnavailable)
		return
	}
	if s.cfg.Features != nil && !s.cfg.Features.ForwardProxy {
		http.Error(w, "Forward proxy disabled", 403)
		return
	}
	// goproxy's CONNECT implementation requires HTTP/1 hijacking. Reject HTTP/2
	// CONNECT explicitly instead of panicking on a ResponseWriter without Hijack.
	if r.ProtoMajor != 1 {
		http.Error(w, "CONNECT requires HTTP/1.1", http.StatusNotImplemented)
		return
	}
	checks := []RequestMiddleware{}
	if s.threatMgr != nil {
		checks = append(checks, s.middlewareThreatIntel)
	}
	if s.geoIP != nil {
		checks = append(checks, s.middlewareGeoIP)
	}
	checks = append(checks, s.middlewareAuth, s.middlewareAccess)
	if s.policyEngine != nil {
		checks = append(checks, s.middlewarePolicy)
	}
	ctx := &goproxy.ProxyCtx{Req: r}
	for _, check := range checks {
		updated, resp := check(r, ctx)
		if updated != nil {
			r = updated
			ctx.Req = r
		}
		if resp == nil {
			continue
		}
		s.recordDecision(r, resp.StatusCode, "CONNECT admission rejected traffic")
		for k, vs := range resp.Header {
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		if resp.Body != nil {
			defer resp.Body.Close()
			io.Copy(w, resp.Body)
		}
		return
	}
	p, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		http.Error(w, "Tunnel identity unavailable", 407)
		return
	}
	identity := tunnelIdentity{Principal: p, TLS: r.TLS}
	r = r.WithContext(context.WithValue(r.Context(), tunnelIdentityKey{}, identity))
	s.proxy.ServeHTTP(&connectResponseWriter{ResponseWriter: w, registry: &s.connectSockets}, r)
}

type connectRegistry struct {
	mu          sync.Mutex
	closed      bool
	connections map[*trackedConnectConn]struct{}
	shutdown    context.Context
	cancel      context.CancelFunc
}

func (r *connectRegistry) shutdownContext() context.Context {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.shutdown == nil {
		r.shutdown, r.cancel = context.WithCancel(context.Background())
		if r.closed {
			r.cancel()
		}
	}
	return r.shutdown
}

func (r *connectRegistry) isClosed() bool { r.mu.Lock(); defer r.mu.Unlock(); return r.closed }
func (r *connectRegistry) track(conn net.Conn) (net.Conn, error) {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		conn.Close()
		return nil, net.ErrClosed
	}
	if r.connections == nil {
		r.connections = make(map[*trackedConnectConn]struct{})
	}
	tracked := &trackedConnectConn{Conn: conn, registry: r}
	r.connections[tracked] = struct{}{}
	r.mu.Unlock()
	if half, ok := conn.(interface {
		CloseRead() error
		CloseWrite() error
	}); ok {
		return &halfClosedConnectConn{trackedConnectConn: tracked, half: half}, nil
	}
	return tracked, nil
}
func (r *connectRegistry) closeAll() {
	r.mu.Lock()
	r.closed = true
	if r.cancel != nil {
		r.cancel()
	}
	connections := make([]*trackedConnectConn, 0, len(r.connections))
	for conn := range r.connections {
		connections = append(connections, conn)
	}
	r.mu.Unlock()
	for _, conn := range connections {
		conn.Close()
	}
}

type trackedConnectConn struct {
	net.Conn
	registry *connectRegistry
	once     sync.Once
	closeErr error
}

func (c *trackedConnectConn) Close() error {
	c.once.Do(func() {
		c.closeErr = c.Conn.Close()
		c.registry.mu.Lock()
		delete(c.registry.connections, c)
		c.registry.mu.Unlock()
	})
	return c.closeErr
}

type halfClosedConnectConn struct {
	*trackedConnectConn
	half interface {
		CloseRead() error
		CloseWrite() error
	}
}

func (c *halfClosedConnectConn) CloseRead() error  { return c.half.CloseRead() }
func (c *halfClosedConnectConn) CloseWrite() error { return c.half.CloseWrite() }

type connectResponseWriter struct {
	http.ResponseWriter
	registry *connectRegistry
}

func (w *connectResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, http.ErrNotSupported
	}
	conn, rw, err := h.Hijack()
	if err != nil {
		return nil, nil, err
	}
	tracked, err := w.registry.track(conn)
	if err != nil {
		// The underlying response is already hijacked. Return the now-closed
		// connection: goproxy handles I/O failure but panics on Hijack errors.
		return conn, rw, nil
	}
	// Preserve the existing buffered reader/writer, including any bytes already
	// read beyond CONNECT headers; both still refer to the same socket.
	return tracked, rw, nil
}

func (s *Server) trackConnectDialer() {
	withReq := s.proxy.ConnectDialWithReq
	legacy := s.proxy.ConnectDial
	var parent *url.URL
	if s.cfg != nil && s.cfg.ParentProxy != "" {
		var err error
		parent, err = url.Parse(s.cfg.ParentProxy)
		if err != nil || parent.Hostname() == "" || (parent.Scheme != "http" && parent.Scheme != "https") {
			s.initErr = errors.Join(s.initErr, fmt.Errorf("CONNECT parent must be an HTTP or HTTPS proxy URL"))
			// Never silently fall back to a direct dial on invalid configuration.
			s.proxy.ConnectDialWithReq = func(*http.Request, string, string) (net.Conn, error) {
				return nil, fmt.Errorf("invalid CONNECT parent configuration")
			}
			return
		}
	}
	s.proxy.ConnectDialWithReq = func(req *http.Request, network, addr string) (net.Conn, error) {
		if s.connectSockets.isClosed() {
			return nil, net.ErrClosed
		}
		ctx, cancel := context.WithCancel(req.Context())
		stop := context.AfterFunc(s.connectSockets.shutdownContext(), cancel)
		defer stop()
		defer cancel()
		req = req.WithContext(ctx)
		var conn net.Conn
		var err error
		switch {
		case parent != nil:
			conn, err = dialParentCONNECT(req.Context(), parent, network, addr)
		case withReq != nil:
			conn, err = withReq(req, network, addr)
		case legacy != nil:
			conn, err = legacy(network, addr)
		case s.proxy.Tr != nil && s.proxy.Tr.DialContext != nil:
			conn, err = s.proxy.Tr.DialContext(req.Context(), network, addr)
		default:
			var d net.Dialer
			conn, err = d.DialContext(req.Context(), network, addr)
		}
		if err != nil {
			return nil, err
		}
		return s.connectSockets.track(conn)
	}
}

// dialParentCONNECT performs a bounded handshake and never copies caller
// credentials. HTTPS parents use normal hostname and certificate verification.
func dialParentCONNECT(ctx context.Context, parent *url.URL, network, addr string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	port := parent.Port()
	if port == "" {
		port = "80"
		if parent.Scheme == "https" {
			port = "443"
		}
	}
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(parent.Hostname(), port))
	if err != nil {
		return nil, err
	}
	rawConn := conn
	stop := context.AfterFunc(ctx, func() { rawConn.Close() })
	defer stop()
	ok := false
	defer func() {
		if !ok {
			conn.Close()
		}
	}()
	deadline, _ := ctx.Deadline()
	if err = conn.SetDeadline(deadline); err != nil {
		return nil, err
	}
	if parent.Scheme == "https" {
		tlsConn := tls.Client(conn, &tls.Config{MinVersion: tls.VersionTLS12, ServerName: parent.Hostname()})
		if err = tlsConn.HandshakeContext(ctx); err != nil {
			return nil, err
		}
		conn = tlsConn
	}
	r := &http.Request{Method: http.MethodConnect, URL: &url.URL{Opaque: addr}, Host: addr, Header: make(http.Header)}
	if parent.User != nil {
		password, _ := parent.User.Password()
		r.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(parent.User.Username()+":"+password)))
	}
	if err = r.Write(conn); err != nil {
		return nil, err
	}
	// Bound response-header parsing, then release the limit for opaque bytes.
	limited := &io.LimitedReader{R: conn, N: 64 << 10}
	reader := bufio.NewReader(limited)
	resp, err := http.ReadResponse(reader, r)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("parent CONNECT returned status %d", resp.StatusCode)
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	if err = conn.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}
	limited.N = 1<<63 - 1
	ok = true
	buffered := &bufferedConnectConn{Conn: conn, reader: reader}
	if half, yes := conn.(interface {
		CloseRead() error
		CloseWrite() error
	}); yes {
		return &bufferedHalfConnectConn{bufferedConnectConn: buffered, half: half}, nil
	}
	return buffered, nil
}

type bufferedConnectConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConnectConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

type bufferedHalfConnectConn struct {
	*bufferedConnectConn
	half interface {
		CloseRead() error
		CloseWrite() error
	}
}

func (c *bufferedHalfConnectConn) CloseRead() error  { return c.half.CloseRead() }
func (c *bufferedHalfConnectConn) CloseWrite() error { return c.half.CloseWrite() }
