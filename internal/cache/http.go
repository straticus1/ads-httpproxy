package cache

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"ads-httpproxy/pkg/logging"

	"go.uber.org/zap"
)

// CachedResponse represents a cached HTTP response
type CachedResponse struct {
	StatusCode     int               `json:"status_code"`
	Headers        map[string]string `json:"headers"`
	Body           []byte            `json:"body"`
	BodyCompressed bool              `json:"body_compressed"`
	ETag           string            `json:"etag"`
	LastModified   string            `json:"last_modified"`
	CachedAt       time.Time         `json:"cached_at"`
	TTL            time.Duration     `json:"ttl"`
	ContentType    string            `json:"content_type"`
	Size           int               `json:"size"`
}

// CacheStats tracks cache performance metrics
type CacheStats struct {
	L1Hits       uint64
	L2Hits       uint64
	Misses       uint64
	Stores       uint64
	Errors       uint64
	BytesSaved   uint64
	BytesStored  uint64
}

// HTTPCache manages HTTP response caching
type HTTPCache struct {
	redis      *Manager
	memory     *MemoryCache
	config     *CacheConfig
	stats      *CacheStats
}

// CacheConfig configures HTTP caching behavior
type CacheConfig struct {
	Enabled         bool
	MemoryEnabled   bool
	MemoryMaxSizeMB int
	MemoryMaxTTL    time.Duration
	DefaultTTL      time.Duration
	MaxTTL          time.Duration
	MinSizeBytes    int64
	MaxSizeBytes    int64
	CompressBody    bool
	CachePrivate    bool // Cache responses with Cache-Control: private
}

// NewHTTPCache creates a new HTTP cache manager
func NewHTTPCache(redis *Manager, config *CacheConfig) *HTTPCache {
	if config == nil {
		config = DefaultCacheConfig()
	}

	hc := &HTTPCache{
		redis:  redis,
		config: config,
		stats:  &CacheStats{},
	}

	// Initialize L1 memory cache if enabled
	if config.MemoryEnabled {
		hc.memory = NewMemoryCache(config.MemoryMaxSizeMB, config.MemoryMaxTTL)
		logging.Logger.Info("HTTP cache L1 (memory) enabled",
			zap.Int("max_size_mb", config.MemoryMaxSizeMB),
			zap.Duration("max_ttl", config.MemoryMaxTTL))
	}

	logging.Logger.Info("HTTP cache initialized",
		zap.Bool("redis_enabled", redis != nil),
		zap.Bool("memory_enabled", config.MemoryEnabled),
		zap.Duration("default_ttl", config.DefaultTTL))

	return hc
}

// DefaultCacheConfig returns default cache configuration
func DefaultCacheConfig() *CacheConfig {
	return &CacheConfig{
		Enabled:         true,
		MemoryEnabled:   true,
		MemoryMaxSizeMB: 500,
		MemoryMaxTTL:    60 * time.Second,
		DefaultTTL:      3600 * time.Second, // 1 hour
		MaxTTL:          86400 * time.Second, // 24 hours
		MinSizeBytes:    1024,                 // 1KB
		MaxSizeBytes:    10 * 1024 * 1024,     // 10MB
		CompressBody:    true,
		CachePrivate:    false,
	}
}

// Get retrieves a cached response
func (hc *HTTPCache) Get(req *http.Request) (*CachedResponse, bool) {
	if hc == nil || !hc.config.Enabled {
		return nil, false
	}

	key := hc.GenerateKey(req)

	// L1 check (memory)
	if hc.memory != nil {
		if data, ok := hc.memory.Get(key); ok {
			cached := &CachedResponse{}
			if err := json.Unmarshal(data, cached); err == nil {
				atomic.AddUint64(&hc.stats.L1Hits, 1)
				atomic.AddUint64(&hc.stats.BytesSaved, uint64(cached.Size))
				logging.Logger.Debug("Cache L1 HIT", zap.String("key", key))
				return cached, true
			}
		}
	}

	// L2 check (Redis)
	if hc.redis != nil {
		if data, ok := hc.redis.Get(key); ok {
			cached := &CachedResponse{}
			if err := json.Unmarshal(data, cached); err == nil {
				// Promote to L1
				if hc.memory != nil {
					hc.memory.Set(key, data, hc.config.MemoryMaxTTL)
				}

				atomic.AddUint64(&hc.stats.L2Hits, 1)
				atomic.AddUint64(&hc.stats.BytesSaved, uint64(cached.Size))
				logging.Logger.Debug("Cache L2 HIT", zap.String("key", key))
				return cached, true
			}
		}
	}

	atomic.AddUint64(&hc.stats.Misses, 1)
	logging.Logger.Debug("Cache MISS", zap.String("key", key))
	return nil, false
}

// Set stores a response in cache
func (hc *HTTPCache) Set(req *http.Request, resp *http.Response) error {
	if hc == nil || !hc.config.Enabled {
		return nil
	}

	// Check if response is cacheable
	if !hc.IsCacheable(req, resp) {
		return nil
	}

	key := hc.GenerateKey(req)
	ttl := hc.CalculateTTL(resp)

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		atomic.AddUint64(&hc.stats.Errors, 1)
		return err
	}
	resp.Body.Close()

	// Restore body for downstream
	resp.Body = io.NopCloser(bytes.NewReader(body))

	// Check size limits
	size := int64(len(body))
	if size < hc.config.MinSizeBytes || size > hc.config.MaxSizeBytes {
		return nil
	}

	// Compress body if enabled
	bodyCompressed := false
	bodyToStore := body
	if hc.config.CompressBody && size > 1024 { // Only compress > 1KB
		var buf bytes.Buffer
		gw := gzip.NewWriter(&buf)
		if _, err := gw.Write(body); err == nil {
			gw.Close()
			compressed := buf.Bytes()
			if len(compressed) < len(body) {
				bodyToStore = compressed
				bodyCompressed = true
			}
		}
	}

	// Create cached response
	cached := &CachedResponse{
		StatusCode:     resp.StatusCode,
		Headers:        flattenHeaders(resp.Header),
		Body:           bodyToStore,
		BodyCompressed: bodyCompressed,
		ETag:           resp.Header.Get("ETag"),
		LastModified:   resp.Header.Get("Last-Modified"),
		CachedAt:       time.Now(),
		TTL:            ttl,
		ContentType:    resp.Header.Get("Content-Type"),
		Size:           int(size),
	}

	// Serialize
	data, err := json.Marshal(cached)
	if err != nil {
		atomic.AddUint64(&hc.stats.Errors, 1)
		return err
	}

	// Store in both tiers
	if hc.redis != nil {
		hc.redis.Set(key, data, ttl)
	}

	if hc.memory != nil {
		memTTL := ttl
		if memTTL > hc.config.MemoryMaxTTL {
			memTTL = hc.config.MemoryMaxTTL
		}
		hc.memory.Set(key, data, memTTL)
	}

	atomic.AddUint64(&hc.stats.Stores, 1)
	atomic.AddUint64(&hc.stats.BytesStored, uint64(len(bodyToStore)))

	logging.Logger.Debug("Cached response",
		zap.String("key", key),
		zap.Int("size", int(size)),
		zap.Duration("ttl", ttl),
		zap.Bool("compressed", bodyCompressed))

	return nil
}

// ToResponse converts CachedResponse to http.Response
func (cr *CachedResponse) ToResponse(req *http.Request) *http.Response {
	body := cr.Body

	// Decompress if needed
	if cr.BodyCompressed {
		gr, err := gzip.NewReader(bytes.NewReader(body))
		if err == nil {
			decompressed, err := io.ReadAll(gr)
			gr.Close()
			if err == nil {
				body = decompressed
			}
		}
	}

	// Build headers
	headers := make(http.Header)
	for k, v := range cr.Headers {
		headers.Set(k, v)
	}

	// Add cache metadata
	headers.Set("X-Cache", "HIT")
	headers.Set("Age", fmt.Sprintf("%d", int(time.Since(cr.CachedAt).Seconds())))
	headers.Set("X-Cache-Lookup", "HIT")

	return &http.Response{
		StatusCode:    cr.StatusCode,
		Header:        headers,
		Body:          io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)),
		Request:       req,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
	}
}

// CheckConditional checks if request can be satisfied with 304 Not Modified
func (cr *CachedResponse) CheckConditional(req *http.Request) bool {
	// If-None-Match (ETag)
	if inm := req.Header.Get("If-None-Match"); inm != "" && cr.ETag != "" {
		if inm == cr.ETag || inm == "*" {
			return true
		}
	}

	// If-Modified-Since
	if ims := req.Header.Get("If-Modified-Since"); ims != "" && cr.LastModified != "" {
		imsTime, err := http.ParseTime(ims)
		if err == nil {
			lmTime, err := http.ParseTime(cr.LastModified)
			if err == nil && !lmTime.After(imsTime) {
				return true
			}
		}
	}

	return false
}

// IsCacheable determines if a response should be cached
func (hc *HTTPCache) IsCacheable(req *http.Request, resp *http.Response) bool {
	// Only cache GET and HEAD
	if req.Method != "GET" && req.Method != "HEAD" {
		return false
	}

	// Only cache successful responses
	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return false
	}

	// Check Cache-Control directives
	cc := parseCacheControl(resp.Header.Get("Cache-Control"))

	// Never cache no-store
	if _, noStore := cc["no-store"]; noStore {
		return false
	}

	// Don't cache private unless configured
	if _, private := cc["private"]; private && !hc.config.CachePrivate {
		return false
	}

	// Don't cache if Pragma: no-cache
	if resp.Header.Get("Pragma") == "no-cache" {
		return false
	}

	// Don't cache responses with Set-Cookie (user-specific)
	if resp.Header.Get("Set-Cookie") != "" {
		return false
	}

	// Don't cache if Authorization header present (unless explicitly public)
	if req.Header.Get("Authorization") != "" {
		if _, public := cc["public"]; !public {
			return false
		}
	}

	// Don't cache if Vary: * (impossible to match)
	if resp.Header.Get("Vary") == "*" {
		return false
	}

	return true
}

// CalculateTTL determines cache TTL from response headers
func (hc *HTTPCache) CalculateTTL(resp *http.Response) time.Duration {
	cc := parseCacheControl(resp.Header.Get("Cache-Control"))

	// s-maxage (shared cache specific)
	if sMaxAge, ok := cc["s-maxage"]; ok {
		if age, err := strconv.Atoi(sMaxAge); err == nil && age > 0 {
			ttl := time.Duration(age) * time.Second
			if ttl > hc.config.MaxTTL {
				ttl = hc.config.MaxTTL
			}
			return ttl
		}
	}

	// max-age
	if maxAge, ok := cc["max-age"]; ok {
		if age, err := strconv.Atoi(maxAge); err == nil && age > 0 {
			ttl := time.Duration(age) * time.Second
			if ttl > hc.config.MaxTTL {
				ttl = hc.config.MaxTTL
			}
			return ttl
		}
	}

	// Expires header
	if expires := resp.Header.Get("Expires"); expires != "" {
		if expTime, err := http.ParseTime(expires); err == nil {
			ttl := time.Until(expTime)
			if ttl > 0 {
				if ttl > hc.config.MaxTTL {
					ttl = hc.config.MaxTTL
				}
				return ttl
			}
		}
	}

	// Use default TTL
	return hc.config.DefaultTTL
}

// GenerateKey creates a cache key for the request
func (hc *HTTPCache) GenerateKey(req *http.Request) string {
	// Sort query parameters for consistent keys
	query := req.URL.Query()
	var keys []string
	for k := range query {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var sortedQuery []string
	for _, k := range keys {
		for _, v := range query[k] {
			sortedQuery = append(sortedQuery, fmt.Sprintf("%s=%s", url.QueryEscape(k), url.QueryEscape(v)))
		}
	}

	// Include Accept-Encoding in key (for Vary support)
	encoding := req.Header.Get("Accept-Encoding")

	// Build key components
	keyStr := fmt.Sprintf("%s:%s://%s%s?%s:%s",
		req.Method,
		req.URL.Scheme,
		req.URL.Host,
		req.URL.Path,
		strings.Join(sortedQuery, "&"),
		encoding,
	)

	// Hash for consistent length
	hash := sha256.Sum256([]byte(keyStr))
	return fmt.Sprintf("cache:http:%x", hash)
}

// Purge removes a specific URL from cache
func (hc *HTTPCache) Purge(urlStr string) error {
	if hc == nil {
		return nil
	}

	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return err
	}

	req := &http.Request{
		Method: "GET",
		URL:    parsedURL,
		Header: make(http.Header),
	}

	key := hc.GenerateKey(req)

	if hc.memory != nil {
		hc.memory.Delete(key)
	}

	if hc.redis != nil {
		hc.redis.Delete(key)
	}

	logging.Logger.Info("Purged cache entry", zap.String("url", urlStr), zap.String("key", key))
	return nil
}

// PurgeAll clears entire cache
func (hc *HTTPCache) PurgeAll() error {
	if hc == nil {
		return nil
	}

	if hc.memory != nil {
		hc.memory.Clear()
	}

	if hc.redis != nil {
		hc.redis.PurgePattern("cache:http:*")
	}

	logging.Logger.Info("Purged all cache entries")
	return nil
}

// Stats returns current cache statistics
func (hc *HTTPCache) Stats() CacheStats {
	if hc == nil {
		return CacheStats{}
	}

	return CacheStats{
		L1Hits:      atomic.LoadUint64(&hc.stats.L1Hits),
		L2Hits:      atomic.LoadUint64(&hc.stats.L2Hits),
		Misses:      atomic.LoadUint64(&hc.stats.Misses),
		Stores:      atomic.LoadUint64(&hc.stats.Stores),
		Errors:      atomic.LoadUint64(&hc.stats.Errors),
		BytesSaved:  atomic.LoadUint64(&hc.stats.BytesSaved),
		BytesStored: atomic.LoadUint64(&hc.stats.BytesStored),
	}
}

// HitRate calculates cache hit rate
func (cs *CacheStats) HitRate() float64 {
	total := cs.L1Hits + cs.L2Hits + cs.Misses
	if total == 0 {
		return 0.0
	}
	return float64(cs.L1Hits+cs.L2Hits) / float64(total)
}

// Helper functions

func parseCacheControl(header string) map[string]string {
	directives := make(map[string]string)
	if header == "" {
		return directives
	}

	parts := strings.Split(header, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if kv := strings.SplitN(part, "=", 2); len(kv) == 2 {
			directives[strings.TrimSpace(kv[0])] = strings.Trim(kv[1], `"`)
		} else {
			directives[part] = "true"
		}
	}

	return directives
}

func flattenHeaders(h http.Header) map[string]string {
	flat := make(map[string]string)
	for k, v := range h {
		if len(v) > 0 {
			flat[k] = v[0]
		}
	}
	return flat
}
