package api

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"

	"ads-httpproxy/internal/adaptive"
	"ads-httpproxy/internal/ai"
	"ads-httpproxy/internal/analysis"
)

func (s *Server) SetPlatform(a *analysis.Manager, e *adaptive.Engine) { s.analysis = a; s.adaptive = e }
func (s *Server) SetIdentityRevoker(f func(string) int)               { s.revokeIdentity = f }
func decodePlatform(w http.ResponseWriter, r *http.Request, v any) bool {
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil || d.Decode(new(any)) != io.EOF {
		http.Error(w, "Invalid JSON request", 400)
		return false
	}
	return true
}
func writePlatform(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(v)
}
func (s *Server) mountPlatform(mux *http.ServeMux) {
	mount := func(path string, h http.HandlerFunc) {
		mux.HandleFunc(path, s.rateLimitMiddleware(func(w http.ResponseWriter, r *http.Request) {
			if s.cfg.ApiSecret == "" && len(s.cfg.ApiUsers) == 0 {
				http.Error(w, "Platform management requires configured API authentication", 503)
				return
			}
			s.authMiddleware(h)(w, r)
		}))
	}
	if s.analysis != nil {
		mount("/api/analysis/findings", s.handleFindings)
		mount("/api/analysis/stats", s.handleAnalysisStats)
	}
	if s.adaptive != nil {
		mount("/api/adaptive/policy", s.handleAdaptive)
		mount("/api/adaptive/preview", s.handleAdaptivePreview)
		mount("/api/adaptive/rollback", s.handleAdaptiveRollback)
	}
	if s.cfg.AI != nil && s.cfg.AI.Enabled {
		mount("/api/ai/explain", s.handleExplain)
	}
	if s.revokeIdentity != nil {
		mount("/api/identity/revoke", s.handleRevoke)
	}
}
func (s *Server) handleFindings(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", 405)
		return
	}
	limit := 100
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > 1000 {
			http.Error(w, "limit must be 1..1000", 400)
			return
		}
		limit = n
	}
	writePlatform(w, map[string]any{"findings": s.analysis.Snapshot(analysis.Filter{Tenant: r.URL.Query().Get("tenant"), Category: r.URL.Query().Get("category"), Limit: limit})})
}
func (s *Server) handleAnalysisStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", 405)
		return
	}
	writePlatform(w, s.analysis.Stats())
}
func (s *Server) handleAdaptive(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		writePlatform(w, map[string]any{"policy": s.adaptive.Snapshot(), "history": s.adaptive.History()})
	case "PUT":
		var v struct {
			ExpectedVersion uint64          `json:"expected_version"`
			Mode            string          `json:"mode"`
			Rules           []adaptive.Rule `json:"rules"`
		}
		if !decodePlatform(w, r, &v) {
			return
		}
		if err := adaptive.Validate(adaptive.Config{Mode: v.Mode, Rules: v.Rules}); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		snap, err := s.adaptive.Replace(v.ExpectedVersion, v.Mode, v.Rules)
		if err != nil {
			http.Error(w, err.Error(), 409)
			return
		}
		writePlatform(w, snap)
	default:
		http.Error(w, "Method not allowed", 405)
	}
}
func (s *Server) handleAdaptivePreview(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", 405)
		return
	}
	var v adaptive.Input
	if !decodePlatform(w, r, &v) {
		return
	}
	writePlatform(w, s.adaptive.Evaluate(v))
}
func (s *Server) handleAdaptiveRollback(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", 405)
		return
	}
	var v struct {
		ExpectedVersion uint64 `json:"expected_version"`
		TargetVersion   uint64 `json:"target_version"`
	}
	if !decodePlatform(w, r, &v) {
		return
	}
	snap, err := s.adaptive.Rollback(v.ExpectedVersion, v.TargetVersion)
	if err != nil {
		http.Error(w, err.Error(), 409)
		return
	}
	writePlatform(w, snap)
}
func (s *Server) handleExplain(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", 405)
		return
	}
	var v struct {
		Question string `json:"question"`
		Tenant   string `json:"tenant"`
		Category string `json:"category"`
		Limit    int    `json:"limit"`
	}
	if !decodePlatform(w, r, &v) {
		return
	}
	if v.Limit < 0 || v.Limit > 100 || len(v.Question) > 4096 {
		http.Error(w, "Explanation input exceeds limits", 400)
		return
	}
	if v.Limit == 0 {
		v.Limit = 50
	}
	var findings []analysis.Finding
	if s.analysis != nil {
		findings = s.analysis.Snapshot(analysis.Filter{Tenant: v.Tenant, Category: v.Category, Limit: v.Limit})
	}
	result, err := ai.Explain(r.Context(), *s.cfg.AI, v.Question, findings)
	if err != nil {
		http.Error(w, err.Error(), 502)
		return
	}
	writePlatform(w, result)
}
func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", 405)
		return
	}
	var v struct {
		Subject string `json:"subject"`
	}
	if !decodePlatform(w, r, &v) {
		return
	}
	if v.Subject == "" || len(v.Subject) > 512 {
		http.Error(w, "subject required (max 512 bytes)", 400)
		return
	}
	writePlatform(w, map[string]int{"revoked_sessions": s.revokeIdentity(v.Subject)})
}
