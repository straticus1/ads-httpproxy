package api

import (
	"encoding/json"
	"fmt"
	"net/http"

	"ads-httpproxy/internal/cache"
	"ads-httpproxy/pkg/logging"

	"go.uber.org/zap"
)

// CacheHandler handles HTTP cache API endpoints
type CacheHandler struct {
	httpCache *cache.HTTPCache
}

// NewCacheHandler creates a new cache handler
func NewCacheHandler(httpCache *cache.HTTPCache) *CacheHandler {
	return &CacheHandler{
		httpCache: httpCache,
	}
}

// HandleStats returns cache statistics
// GET /api/cache/stats
func (h *CacheHandler) HandleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if h.httpCache == nil {
		http.Error(w, "Cache not enabled", http.StatusServiceUnavailable)
		return
	}

	stats := h.httpCache.Stats()

	response := map[string]interface{}{
		"l1_hits":             stats.L1Hits,
		"l2_hits":             stats.L2Hits,
		"misses":              stats.Misses,
		"stores":              stats.Stores,
		"errors":              stats.Errors,
		"hit_rate":            stats.HitRate(),
		"bytes_saved":         stats.BytesSaved,
		"bytes_saved_gb":      float64(stats.BytesSaved) / (1024 * 1024 * 1024),
		"bytes_stored":        stats.BytesStored,
		"bytes_stored_gb":     float64(stats.BytesStored) / (1024 * 1024 * 1024),
		"total_requests":      stats.L1Hits + stats.L2Hits + stats.Misses,
		"compression_ratio":   calculateCompressionRatio(stats),
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		logging.Logger.Error("Failed to encode cache stats", zap.Error(err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// HandlePurge purges a specific URL from cache
// DELETE /api/cache/purge?url=https://example.com/page
// PURGE /cache/https://example.com/page
func (h *CacheHandler) HandlePurge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete && r.Method != "PURGE" {
		http.Error(w, "Method not allowed (use DELETE or PURGE)", http.StatusMethodNotAllowed)
		return
	}

	if h.httpCache == nil {
		http.Error(w, "Cache not enabled", http.StatusServiceUnavailable)
		return
	}

	// Get URL from query parameter or request path
	urlStr := r.URL.Query().Get("url")
	if urlStr == "" {
		// Try to get from path (e.g., /cache/https://example.com/page)
		urlStr = r.URL.Path
		if len(urlStr) > 7 && urlStr[:7] == "/cache/" {
			urlStr = urlStr[7:]
		}
	}

	if urlStr == "" {
		http.Error(w, "Missing 'url' parameter", http.StatusBadRequest)
		return
	}

	if err := h.httpCache.Purge(urlStr); err != nil {
		logging.Logger.Error("Cache purge failed", zap.String("url", urlStr), zap.Error(err))
		http.Error(w, fmt.Sprintf("Purge failed: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "success",
		"message": "Cache entry purged",
		"url":     urlStr,
	})
}

// HandlePurgeAll clears entire cache
// DELETE /api/cache/all
func (h *CacheHandler) HandlePurgeAll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if h.httpCache == nil {
		http.Error(w, "Cache not enabled", http.StatusServiceUnavailable)
		return
	}

	if err := h.httpCache.PurgeAll(); err != nil {
		logging.Logger.Error("Cache purge all failed", zap.Error(err))
		http.Error(w, fmt.Sprintf("Purge all failed: %v", err), http.StatusInternalServerError)
		return
	}

	logging.Logger.Info("Cache purged via API")

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "success",
		"message": "All cache entries purged",
	})
}

// HandleHealth checks cache health
// GET /api/cache/health
func (h *CacheHandler) HandleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	health := map[string]interface{}{
		"enabled": h.httpCache != nil,
		"status":  "ok",
	}

	if h.httpCache == nil {
		health["status"] = "disabled"
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(health)
}

func calculateCompressionRatio(stats cache.CacheStats) float64 {
	if stats.BytesStored == 0 {
		return 1.0
	}
	// This is an approximation - actual ratio would need more detailed tracking
	return float64(stats.BytesSaved) / float64(stats.BytesStored)
}
