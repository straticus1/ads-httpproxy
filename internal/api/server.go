package api

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"os"
	"strings"

	"ads-httpproxy/internal/api/ui"
	"ads-httpproxy/internal/bandwidth"
	"ads-httpproxy/internal/config"
	"ads-httpproxy/internal/pac"
	"ads-httpproxy/internal/plugin"
	"ads-httpproxy/internal/visibility"
	"ads-httpproxy/pkg/logging"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
)

// Server represents the Admin API server.
type Server struct {
	cfg          *config.Config
	limiter      bandwidth.Limiter
	apiLimiter   bandwidth.Limiter
	cacheHandler *CacheHandler
	pluginMgr    *plugin.Manager
}

// NewServer creates a new Admin API server.
func NewServer(cfg *config.Config, limiter bandwidth.Limiter, pm *plugin.Manager) *Server {
	var apiLimiter bandwidth.Limiter
	if cfg.ApiRateLimit > 0 {
		apiLimiter = bandwidth.NewLocalLimiter(float64(cfg.ApiRateLimit), cfg.ApiRateLimit)
	}

	return &Server{
		cfg:        cfg,
		limiter:    limiter,
		apiLimiter: apiLimiter,
		pluginMgr:  pm,
	}
}

// SetCacheHandler sets the cache handler (called after Server creation)
func (s *Server) SetCacheHandler(handler *CacheHandler) {
	s.cacheHandler = handler
}

// Start runs the API server in a background goroutine.
func (s *Server) Start() {
	mux := http.NewServeMux()
	mux.HandleFunc("/stats", s.rateLimitMiddleware(s.authMiddleware(s.handleStats)))
	mux.HandleFunc("/connections", s.rateLimitMiddleware(s.authMiddleware(s.handleConnections)))
	mux.HandleFunc("/config", s.rateLimitMiddleware(s.authMiddleware(s.handleConfig)))
	mux.HandleFunc("/healthz", s.handleHealth)
	mux.Handle("/metrics", promhttp.Handler())

	// Plugin endpoints
	mux.HandleFunc("/plugins", s.rateLimitMiddleware(s.authMiddleware(s.handlePluginsList)))
	mux.HandleFunc("/plugins/load", s.rateLimitMiddleware(s.authMiddleware(s.handlePluginsLoad)))
	mux.HandleFunc("/plugins/unload", s.rateLimitMiddleware(s.authMiddleware(s.handlePluginsUnload)))

	// Cache API endpoints
	if s.cacheHandler != nil {
		mux.HandleFunc("/api/cache/stats", s.rateLimitMiddleware(s.authMiddleware(s.cacheHandler.HandleStats)))
		mux.HandleFunc("/api/cache/purge", s.rateLimitMiddleware(s.authMiddleware(s.cacheHandler.HandlePurge)))
		mux.HandleFunc("/api/cache/all", s.rateLimitMiddleware(s.authMiddleware(s.cacheHandler.HandlePurgeAll)))
		mux.HandleFunc("/api/cache/health", s.cacheHandler.HandleHealth)
		// Support PURGE method on /cache/* paths
		mux.HandleFunc("/cache/", s.rateLimitMiddleware(s.authMiddleware(s.cacheHandler.HandlePurge)))
	}

	// Serve Embedded Real-Time Dashboard
	mux.HandleFunc("/ui/", func(w http.ResponseWriter, r *http.Request) {
		content, err := ui.Content.ReadFile("index.html")
		if err != nil {
			http.Error(w, "Dashboard not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(content)
	})

	pacHandler := pac.NewHandler(s.cfg.Addr)
	mux.Handle("/proxy.pac", pacHandler)
	mux.Handle("/api/pac/policy", http.HandlerFunc(pacHandler.HandleAPI))

	logging.Logger.Info("Starting Admin API", zap.String("addr", s.cfg.ApiAddr))
	go func() {
		if s.cfg.ApiCert != "" && s.cfg.ApiPrivKey != "" {
			logging.Logger.Info("Using TLS for Admin API")

			tlsConfig := &tls.Config{}
			if s.cfg.ApiClientCA != "" {
				caCert, err := os.ReadFile(s.cfg.ApiClientCA)
				if err != nil {
					logging.Logger.Error("Failed to read API Client CA", zap.Error(err))
				} else {
					caCertPool := x509.NewCertPool()
					caCertPool.AppendCertsFromPEM(caCert)
					tlsConfig.ClientCAs = caCertPool
					tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
					logging.Logger.Info("Enabled Client Certificate Authentication (mTLS) for Admin API")
				}
			}

			server := &http.Server{
				Addr:      s.cfg.ApiAddr,
				Handler:   mux,
				TLSConfig: tlsConfig,
			}
			if err := server.ListenAndServeTLS(s.cfg.ApiCert, s.cfg.ApiPrivKey); err != nil {
				logging.Logger.Error("Admin API TLS failed", zap.Error(err))
			}
		} else {
			if err := http.ListenAndServe(s.cfg.ApiAddr, mux); err != nil {
				logging.Logger.Error("Admin API failed", zap.Error(err))
			}
		}
	}()
}

func (s *Server) rateLimitMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.apiLimiter != nil {
			if err := s.apiLimiter.WaitN(r.Context(), 1); err != nil {
				http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
				return
			}
		}
		next(w, r)
	}
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
		http.Error(w, "live configuration replacement is disabled; validate a configuration file and restart the service", http.StatusNotImplemented)
		return
	}

	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	redacted, err := redactedConfig(s.cfg)
	if err != nil {
		http.Error(w, "Failed to redact config", http.StatusInternalServerError)
		return
	}
	if err := json.NewEncoder(w).Encode(redacted); err != nil {
		logging.Logger.Error("Failed to encode config", zap.Error(err))
	}
}

func redactedConfig(cfg *config.Config) (map[string]interface{}, error) {
	data, err := json.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	var value map[string]interface{}
	if err := json.Unmarshal(data, &value); err != nil {
		return nil, err
	}
	redactJSONSecrets(value)
	return value, nil
}

func redactJSONSecrets(value map[string]interface{}) {
	for key, item := range value {
		lower := strings.ToLower(key)
		if strings.Contains(lower, "secret") || strings.Contains(lower, "password") ||
			lower == "api_key" || strings.HasSuffix(lower, "users") || strings.Contains(lower, "privkey") {
			if entries, ok := item.(map[string]interface{}); ok {
				for entry := range entries {
					entries[entry] = "[REDACTED]"
				}
				value[key] = entries
			} else {
				value[key] = "[REDACTED]"
			}
			continue
		}
		if nested, ok := item.(map[string]interface{}); ok {
			redactJSONSecrets(nested)
		}
	}
}

func (s *Server) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Log the audit operations
		logging.Logger.Info("API Audit",
			zap.String("method", r.Method),
			zap.String("path", r.URL.Path),
			zap.String("remote_addr", r.RemoteAddr),
		)

		if s.cfg.ApiSecret == "" && len(s.cfg.ApiUsers) == 0 {
			next(w, r)
			return
		}

		if s.cfg.ApiSecret != "" {
			if apiKey := r.Header.Get("X-API-Key"); apiKey == s.cfg.ApiSecret {
				next(w, r)
				return
			}
		}

		if len(s.cfg.ApiUsers) > 0 {
			if user, pass, ok := r.BasicAuth(); ok {
				if expectedPass, exists := s.cfg.ApiUsers[user]; exists && pass == expectedPass {
					next(w, r)
					return
				}
			}
		}

		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	health := map[string]interface{}{
		"status": "UP",
		"components": map[string]string{
			"api": "UP",
		},
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(health); err != nil {
		logging.Logger.Error("Failed to encode health status", zap.Error(err))
	}
}

func (s *Server) handlePluginsList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.pluginMgr == nil {
		http.Error(w, "Plugin manager not initialized", http.StatusServiceUnavailable)
		return
	}
	plugins := s.pluginMgr.List()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"plugins": plugins})
}

func (s *Server) handlePluginsLoad(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.pluginMgr == nil {
		http.Error(w, "Plugin manager not initialized", http.StatusServiceUnavailable)
		return
	}

	var req struct {
		Path string `json:"path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Path == "" {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	loader := plugin.NewLoader(s.pluginMgr)
	if err := loader.LoadFromFile(req.Path); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"loaded"}`))
}

func (s *Server) handlePluginsUnload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.pluginMgr == nil {
		http.Error(w, "Plugin manager not initialized", http.StatusServiceUnavailable)
		return
	}

	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if err := s.pluginMgr.Remove(req.Name); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"unloaded"}`))
}
