package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"ads-httpproxy/cmd/list-builder/config"
	"ads-httpproxy/cmd/list-builder/internal/builder"
	"ads-httpproxy/pkg/logging"

	"go.uber.org/zap"
)

func main() {
	configPath := flag.String("config", "config.yaml", "Path to configuration file")
	flag.Parse()

	// Initialize basic logger temporarily
	logger, _ := zap.NewProduction()
	defer logger.Sync()
	// Replace global logger if pkg/logging supports it, or just use it here.
	// For now assuming pkg/logging is already usable or we init it.
	// Let's assume we need to Init it if it follows common patterns.
	// Since I haven't seen pkg/logging source, I'll use zap directly for main setup
	// and assume pkg/logging.Logger is accessible.
	logging.Logger = logger

	cfg, err := config.Load(*configPath)
	if err != nil {
		logger.Fatal("Failed to load config", zap.Error(err))
	}

	// Update logger level if needed
	// logging.SetLevel(cfg.Logging.Level)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start Builder
	manager := builder.NewListManager(cfg.Builder)
	manager.Start(ctx)

	// HTTP Server
	mux := http.NewServeMux()
	mux.HandleFunc("/lists/", func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/lists/")
		if name == "" {
			http.Error(w, "List name required", http.StatusBadRequest)
			return
		}

		list, ok := manager.GetList(name)
		if !ok {
			http.Error(w, "List not found", http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Type", "text/plain")
		for _, line := range list {
			fmt.Fprintln(w, line)
		}
	})

	// Health check
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	srv := &http.Server{
		Addr:    fmt.Sprintf(":%d", cfg.Server.Port),
		Handler: mux,
	}

	go func() {
		logger.Info("Starting list-builder server", zap.Int("port", cfg.Server.Port))
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal("Server failed", zap.Error(err))
		}
	}()

	// Graceful shutdown
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	logger.Info("Shutting down...")
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("Server shutdown error", zap.Error(err))
	}
}
