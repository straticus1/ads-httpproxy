package api

import (
	"encoding/json"
	"net/http"

	"ads-httpproxy/internal/bandwidth"
	"ads-httpproxy/internal/config"
	"ads-httpproxy/internal/pac"
	"ads-httpproxy/internal/visibility"
	"ads-httpproxy/pkg/logging"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
)

// Server represents the Admin API server.
type Server struct {
	cfg     *config.Config
	limiter bandwidth.Limiter
}

// NewServer creates a new Admin API server.
func NewServer(cfg *config.Config, limiter bandwidth.Limiter) *Server {
	return &Server{
		cfg:     cfg,
		limiter: limiter,
	}
}

// Start runs the API server in a background goroutine.
func (s *Server) Start() {
	mux := http.NewServeMux()
	mux.HandleFunc("/stats", s.authMiddleware(s.handleStats))
	mux.HandleFunc("/connections", s.authMiddleware(s.handleConnections))
	mux.HandleFunc("/config", s.authMiddleware(s.handleConfig))
	mux.HandleFunc("/healthz", s.handleHealth)
	mux.Handle("/metrics", promhttp.Handler())

	pacHandler := pac.NewHandler(s.cfg.Addr)
	mux.Handle("/proxy.pac", pacHandler)
	mux.Handle("/api/pac/policy", http.HandlerFunc(pacHandler.HandleAPI))

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

func (s *Server) handleConnections(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	conns := visibility.GetActiveConnections()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(conns); err != nil {
		logging.Logger.Error("Failed to encode connections", zap.Error(err))
	}
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		// Update config
		var newCfg config.Config
		if err := json.NewDecoder(r.Body).Decode(&newCfg); err != nil {
			http.Error(w, "Invalid config json", http.StatusBadRequest)
			return
		}

		// Basic validation & apply (This is a simplified apply, deep dynamic reload is complex)
		// For now we update the struct which might affect some readers, but restart is often needed for deep changes.
		// However, simple flags can be toggled.
		// TODO: Deep validation
		*s.cfg = newCfg

		logging.Logger.Info("Config updated via API")
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(s.cfg); err != nil {
		logging.Logger.Error("Failed to encode config", zap.Error(err))
	}
}

func (s *Server) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Public endpoints are not wrapped, so we only check here.
		// If ApiSecret is empty (not recommended), we might allow all or block all.
		// Assuming secured by default if secret is set.
		if s.cfg.ApiSecret != "" {
			apiKey := r.Header.Get("X-API-Key")
			if apiKey != s.cfg.ApiSecret {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
		}
		next(w, r)
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}
