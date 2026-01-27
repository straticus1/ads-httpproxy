package api

import (
	"encoding/json"
	"net/http"

	"ads-httpproxy/internal/bandwidth"
	"ads-httpproxy/internal/config"
	"ads-httpproxy/internal/pac"
	"ads-httpproxy/internal/visibility"
	"ads-httpproxy/pkg/logging"

	"go.uber.org/zap"
)

// Server represents the Admin API server.
type Server struct {
	cfg     *config.Config
	limiter *bandwidth.Limiter
}

// NewServer creates a new Admin API server.
func NewServer(cfg *config.Config, limiter *bandwidth.Limiter) *Server {
	return &Server{
		cfg:     cfg,
		limiter: limiter,
	}
}

// Start runs the API server in a background goroutine.
func (s *Server) Start() {
	mux := http.NewServeMux()
	mux.HandleFunc("/stats", s.handleStats)

	pacHandler := pac.NewHandler(s.cfg.Addr)
	mux.Handle("/proxy.pac", pacHandler)

	logging.Logger.Info("Starting Admin API", zap.String("addr", s.cfg.ApiAddr))
	go func() {
		if err := http.ListenAndServe(s.cfg.ApiAddr, mux); err != nil {
			logging.Logger.Error("Admin API failed", zap.Error(err))
		}
	}()
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	stats := visibility.GetStats()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(stats); err != nil {
		logging.Logger.Error("Failed to encode stats", zap.Error(err))
	}
}
