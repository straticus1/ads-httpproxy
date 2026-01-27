package main

import (
	"io"
	"net"
	"os"
	"os/signal"
	"syscall"

	"ads-httpproxy/internal/config"
	"ads-httpproxy/internal/proxy"
	"ads-httpproxy/pkg/logging"
	"ads-httpproxy/pkg/mirror"

	"go.uber.org/zap"
)

func main() {
	if err := logging.Init(); err != nil {
		panic(err)
	}
	defer logging.Sync()

	cfg := config.NewConfig()

	// Helper to create listener with optional mirroring
	listen := func(addr string) (net.Listener, error) {
		l, err := net.Listen("tcp", addr)
		if err != nil {
			return nil, err
		}
		if cfg.MirrorAddr != "" {
			logging.Logger.Info("Mirroring enabled", zap.String("mirror", cfg.MirrorAddr))
			return &mirror.Listener{
				Listener: l,
				MirrorFactory: func(remoteAddr net.Addr) io.Writer {
					// Connect to mirror destination for each connection
					c, err := net.Dial("tcp", cfg.MirrorAddr)
					if err != nil {
						logging.Logger.Error("Failed to dial mirror", zap.Error(err))
						return nil
					}
					return c
				},
			}, nil
		}
		return l, nil
	}

	// HTTP Listener
	httpListener, err := listen(cfg.Addr)
	if err != nil {
		logging.Logger.Fatal("Failed to listen for HTTP", zap.Error(err))
	}

	srv := proxy.NewServer(cfg)
	socksSrv, err := proxy.NewSocksServer(cfg.SocksAddr)
	if err != nil {
		logging.Logger.Fatal("Failed to init socks server", zap.Error(err))
	}

	// SOCKS Listener
	socksListener, err := listen(cfg.SocksAddr)
	if err != nil {
		logging.Logger.Fatal("Failed to listen for SOCKS", zap.Error(err))
	}

	// Run HTTP server
	go func() {
		if err := srv.Serve(httpListener); err != nil {
			logging.Logger.Fatal("HTTP Server failed", zap.Error(err))
		}
	}()

	// Run SOCKS server
	go func() {
		if err := socksSrv.Serve(socksListener); err != nil {
			logging.Logger.Fatal("SOCKS Server failed", zap.Error(err))
		}
	}()

	// Wait for interrupt signal using a channel
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logging.Logger.Info("Shutting down server...")
}
