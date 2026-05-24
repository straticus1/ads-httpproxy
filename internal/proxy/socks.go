package proxy

import (
	"errors"
	"log"
	"net"
	"sync"

	"ads-httpproxy/internal/config"
	"ads-httpproxy/pkg/logging"

	"github.com/armon/go-socks5"
	"go.uber.org/zap"
)

type SocksServer struct {
	addr     string
	server   *socks5.Server
	listener net.Listener
	mu       sync.Mutex
}

// NewSocksServer creates a SOCKS5 server. It refuses to start without
// credentials unless the auth config explicitly sets allow_unauthenticated=true,
// preventing accidental open-relay deployment.
func NewSocksServer(addr string, authCfg *config.AuthConfig) (*SocksServer, error) {
	conf := &socks5.Config{
		Logger: log.New(&zapWriter{logging.Logger}, "", 0),
	}

	hasCredentials := authCfg != nil && len(authCfg.Users) > 0
	allowOpen := authCfg != nil && authCfg.AllowUnauthenticated

	switch {
	case hasCredentials:
		conf.Credentials = socks5.StaticCredentials(authCfg.Users)
		conf.AuthMethods = []socks5.Authenticator{socks5.UserPassAuthenticator{
			Credentials: socks5.StaticCredentials(authCfg.Users),
		}}
		logging.Logger.Info("SOCKS5 authentication enabled", zap.Int("users", len(authCfg.Users)))

	case allowOpen:
		// Operator has explicitly chosen to run without authentication.
		// No credentials configured — all clients are permitted.
		logging.Logger.Warn("SOCKS5 running WITHOUT authentication (allow_unauthenticated=true) — ensure this port is not publicly reachable")

	default:
		// Neither credentials nor explicit allow_unauthenticated: refuse to start.
		return nil, errors.New(
			"SOCKS5 refused to start: no credentials configured and allow_unauthenticated is not set. " +
				"Set auth.users or auth.allow_unauthenticated=true (only safe on private interfaces)",
		)
	}

	server, err := socks5.New(conf)
	if err != nil {
		return nil, err
	}
	return &SocksServer{
		addr:   addr,
		server: server,
	}, nil
}

func (s *SocksServer) Serve(l net.Listener) error {
	s.mu.Lock()
	s.listener = l
	s.mu.Unlock()
	logging.Logger.Info("Starting SOCKS5 server", zap.String("addr", l.Addr().String()))
	return s.server.Serve(l)
}

// Shutdown closes the listener, causing Serve to return and stopping new
// connections from being accepted. Active connections are not forcibly closed.
func (s *SocksServer) Shutdown() {
	s.mu.Lock()
	l := s.listener
	s.mu.Unlock()
	if l != nil {
		if err := l.Close(); err != nil {
			logging.Logger.Warn("Error closing SOCKS5 listener", zap.Error(err))
		}
	}
}

// zapWriter adapts zap logger to io.Writer for std log compatibility if needed
type zapWriter struct {
	logger *zap.Logger
}

func (w *zapWriter) Write(p []byte) (n int, err error) {
	w.logger.Debug(string(p))
	return len(p), nil
}
