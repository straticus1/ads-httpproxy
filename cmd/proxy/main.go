package main

import (
	"context"
	"flag"
	"io"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"ads-httpproxy/internal/config"
	"ads-httpproxy/internal/grpc"
	"ads-httpproxy/internal/ja3"
	"ads-httpproxy/internal/protocol"
	"ads-httpproxy/internal/proxy"
	"ads-httpproxy/pkg/logging"
	"ads-httpproxy/pkg/mirror"

	"go.uber.org/zap"
)

func main() {
	configFile := flag.String("config", "", "Path to configuration file")
	flag.Parse()

	if err := logging.Init(); err != nil {
		panic(err)
	}
	defer logging.Sync()

	var cfg *config.Config
	if *configFile != "" {
		var err error
		cfg, err = config.Load(*configFile)
		if err != nil {
			// We can't use zap here easily if logging init failed, but we init logging first.
			// However, logging might be configured IN config later?
			// For now, logging init is hardcoded to defaults/env likely.
			logging.Logger.Fatal("Failed to load config", zap.String("path", *configFile), zap.Error(err))
		}
		logging.Logger.Info("Loaded configuration", zap.String("path", *configFile))
	} else {
		cfg = config.NewConfig()
		if err := cfg.LoadEnv(); err != nil {
			logging.Logger.Fatal("Failed to load env vars", zap.Error(err))
		}
		logging.Logger.Info("Using default configuration")
	}

	// Helper to create listener with optional mirroring
	listen := func(addr string) (net.Listener, error) {
		lc := net.ListenConfig{}
		if cfg.EnableReusePort {
			lc.Control = func(network, address string, c syscall.RawConn) error {
				var opErr error
				err := c.Control(func(fd uintptr) {
					opErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEPORT, 1)
				})
				if err != nil {
					return err
				}
				return opErr
			}
		}
		l, err := lc.Listen(context.Background(), "tcp", addr)
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
	// Wrap with Protocol Safeguard (First line of defense)
	httpListener = protocol.NewListener(httpListener)
	// Wrap with JA3 Sniffer
	httpListener = ja3.NewListener(httpListener)

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
	// Wrap SOCKS with Protocol Safeguard too
	socksListener = protocol.NewListener(socksListener)

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

	// Run RTMP Proxy if configured
	if cfg.RtmpAddr != "" {
		p := proxy.NewTCPProxy(cfg.RtmpAddr, cfg.RtmpTarget)
		l, err := listen(cfg.RtmpAddr)
		if err != nil {
			logging.Logger.Fatal("Failed to listen for RTMP", zap.Error(err))
		}
		go func() {
			if err := p.Serve(l); err != nil {
				logging.Logger.Fatal("RTMP Proxy failed", zap.Error(err))
			}
		}()
	}

	// Run RTSP Proxy if configured
	if cfg.RtspAddr != "" {
		p := proxy.NewTCPProxy(cfg.RtspAddr, cfg.RtspTarget)
		l, err := listen(cfg.RtspAddr)
		if err != nil {
			logging.Logger.Fatal("Failed to listen for RTSP", zap.Error(err))
		}
		go func() {
			if err := p.Serve(l); err != nil {
				logging.Logger.Fatal("RTSP Proxy failed", zap.Error(err))
			}
		}()
	}

	// Run gRPC Admin Server if configured
	if cfg.GrpcAddr != "" {
		gs := grpc.NewServer(cfg)
		gs.Start(cfg.GrpcAddr)
	}

	// Wait for interrupt signal using a channel
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logging.Logger.Info("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		logging.Logger.Error("Server forced to shutdown", zap.Error(err))
	}

	logging.Logger.Info("Server exited")
}
