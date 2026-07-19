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

// dialMirror attempts to connect to addr, retrying up to maxAttempts times
// with simple linear backoff. Returns nil if all attempts fail.
func dialMirror(addr string, maxAttempts int) net.Conn {
	for i := 0; i < maxAttempts; i++ {
		if i > 0 {
			time.Sleep(time.Duration(i) * 200 * time.Millisecond)
		}
		c, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err == nil {
			return c
		}
		logging.Logger.Warn("Failed to dial mirror",
			zap.String("addr", addr),
			zap.Int("attempt", i+1),
			zap.Int("max_attempts", maxAttempts),
			zap.Error(err),
		)
	}
	logging.Logger.Error("Mirror destination unreachable after all attempts, mirroring disabled for this connection",
		zap.String("addr", addr),
		zap.Int("attempts", maxAttempts),
	)
	return nil
}

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
		if err := cfg.Validate(); err != nil {
			logging.Logger.Fatal("Invalid configuration", zap.Error(err))
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
					opErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, SO_REUSEPORT, 1)
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
					c := dialMirror(cfg.MirrorAddr, 3)
					if c == nil {
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
	var socksSrv *proxy.SocksServer
	var socksListener net.Listener
	if cfg.SocksAddr != "" {
		socksSrv, err = proxy.NewSocksServer(cfg.SocksAddr, cfg.Auth)
		if err != nil {
			logging.Logger.Fatal("Failed to init socks server", zap.Error(err))
		}
		socksListener, err = listen(cfg.SocksAddr)
		if err != nil {
			logging.Logger.Fatal("Failed to listen for SOCKS", zap.Error(err))
		}
		socksListener = protocol.NewListener(socksListener)
	}

	// Run HTTP server
	go func() {
		if err := srv.Serve(httpListener); err != nil {
			logging.Logger.Fatal("HTTP Server failed", zap.Error(err))
		}
	}()

	// Run SOCKS server
	if socksSrv != nil {
		go func() {
			if err := socksSrv.Serve(socksListener); err != nil {
				logging.Logger.Fatal("SOCKS Server failed", zap.Error(err))
			}
		}()
	}

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

	if socksSrv != nil {
		socksSrv.Shutdown()
	}

	if err := srv.Shutdown(ctx); err != nil {
		logging.Logger.Error("Server forced to shutdown", zap.Error(err))
	}

	logging.Logger.Info("Server exited")
}
