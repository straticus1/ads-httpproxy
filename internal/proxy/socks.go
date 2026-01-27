package proxy

import (
	"log"
	"net"

	"ads-httpproxy/pkg/logging"

	"github.com/armon/go-socks5"
	"go.uber.org/zap"
)

type SocksServer struct {
	addr   string
	server *socks5.Server
}

func NewSocksServer(addr string) (*SocksServer, error) {
	conf := &socks5.Config{
		Logger: log.New(&zapWriter{logging.Logger}, "", 0), // Adapt zap to standard log needed by socks5
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
	logging.Logger.Info("Starting SOCKS5 server", zap.String("addr", l.Addr().String()))
	return s.server.Serve(l)
}

// zapWriter adapts zap logger to io.Writer for std log compatibility if needed
type zapWriter struct {
	logger *zap.Logger
}

func (w *zapWriter) Write(p []byte) (n int, err error) {
	w.logger.Debug(string(p))
	return len(p), nil
}
