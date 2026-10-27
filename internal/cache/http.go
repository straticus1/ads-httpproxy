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
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"ads-httpproxy/pkg/logging"

	"go.uber.org/zap"
)

// CachedResponse represents a cached HTTP response
type CachedResponse struct {
	StatusCode     int           `json:"status_code"`
	Headers        http.Header   `json:"headers"`
	Body           []byte        `json:"body"`
	BodyCompressed bool          `json:"body_compressed"`
	ETag           string        `json:"etag"`
	LastModified   string        `json:"last_modified"`
	CachedAt       time.Time     `json:"cached_at"`
	TTL            time.Duration `json:"ttl"`
	ContentType    string        `json:"content_type"`
	Size           int           `json:"size"`
}

// CacheStats tracks cache performance metrics
type CacheStats struct {
	L1Hits      uint64
	L2Hits      uint64
	Misses      uint64
	Stores      uint64
	Errors      uint64
	BytesSaved  uint64
	BytesStored uint64
}

// HTTPCache manages HTTP response caching
type HTTPCache struct {
	redis               *Manager
	memory              *MemoryCache
	config              *CacheConfig
	stats               *CacheStats
	generationMu        sync.RWMutex
	generations         [generationPartitions]uint64
	epoch               uint64
	invalidationsFailed atomic.Bool
}

type prefixReadCloser struct {
	io.Reader
	closer io.Closer
}

func (r *prefixReadCloser) Close() error { return r.closer.Close() }

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
	CachePrivate    bool // Deprecated: shared caches always bypass private responses.
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
		DefaultTTL:      3600 * time.Second,  // 1 hour
		MaxTTL:          86400 * time.Second, // 24 hours
		MinSizeBytes:    1024,                // 1KB
		MaxSizeBytes:    10 * 1024 * 1024,    // 10MB
		CompressBody:    true,
		CachePrivate:    false,
	}
}

// Get retrieves a cached response
func (hc *HTTPCache) Get(req *http.Request) (*CachedResponse, bool) {
	if hc == nil || !hc.config.Enabled || !cacheableRequest(req) {
		return nil, false
	}

	generation := hc.Begin(req)
	if !generation.valid {
		return nil, false
	}
	key := hc.generationKey(req, generation)

	// L1 check (memory)
	if hc.memory != nil {
		if data, ok := hc.memory.Get(key); ok {
			cached := &CachedResponse{}
			if err := json.Unmarshal(data, cached); err == nil && time.Now().Before(cached.CachedAt.Add(cached.TTL)) {
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
			if err := json.Unmarshal(data, cached); err == nil && time.Now().Before(cached.CachedAt.Add(cached.TTL)) {
				// Promote to L1
				if hc.memory != nil {
					hc.memory.Set(key, data, time.Until(cached.CachedAt.Add(cached.TTL)))
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
	return hc.SetIfCurrent(req, resp, hc.Begin(req))
}

// SetIfCurrent stores only in the namespace captured before the upstream fetch.
// Old namespaces are unreachable after invalidation and expire normally.
func (hc *HTTPCache) SetIfCurrent(req *http.Request, resp *http.Response, generation Generation) error {
	if hc == nil || !hc.config.Enabled {
		return nil
	}

	// Check if response is cacheable
	if !generation.valid || hc.invalidationsFailed.Load() || !hc.IsCacheable(req, resp) {
		return nil
	}

	resource, _ := resourceKey(req)
	if generation.resource != resource {
		return nil
	}
	key := hc.generationKey(req, generation)
	cachedAt := time.Now()
	ttl := hc.CalculateTTL(resp)
	if ttl <= 0 || resp.Body == nil || resp.ContentLength < 0 || resp.ContentLength > hc.config.MaxSizeBytes {
		return nil
	}

	// Read at most one byte beyond the cache limit. If the response is too
	// large, put the consumed prefix back in front of the original stream so
	// downstream clients still receive the complete response without buffering
	// it all in memory.
	limit := hc.config.MaxSizeBytes
	if limit < 0 {
		limit = 0
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		atomic.AddUint64(&hc.stats.Errors, 1)
		resp.Body = &prefixReadCloser{Reader: io.MultiReader(bytes.NewReader(body), failedReader{err}), closer: resp.Body}
		return err
	}
	if int64(len(body)) > hc.config.MaxSizeBytes {
		resp.Body = &prefixReadCloser{
			Reader: io.MultiReader(bytes.NewReader(body), resp.Body),
			closer: resp.Body,
		}
		return nil
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
		Headers:        resp.Header.Clone(),
		Body:           bodyToStore,
		BodyCompressed: bodyCompressed,
		ETag:           resp.Header.Get("ETag"),
		LastModified:   resp.Header.Get("Last-Modified"),
		CachedAt:       cachedAt,
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
		if err := hc.redis.SetSync(key, data, time.Until(cachedAt.Add(ttl))); err != nil {
			atomic.AddUint64(&hc.stats.Errors, 1)
			return err
		}
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
	headers := cr.Headers.Clone()
	if headers == nil {
		headers = make(http.Header)
	}

	// Add cache metadata
	headers.Set("X-Cache", "HIT")
	age := time.Since(cr.CachedAt)
	if value, err := strconv.ParseInt(headers.Get("Age"), 10, 64); err == nil && value > 0 && value < int64((1<<63-1)/int64(time.Second)) {
		age += time.Duration(value) * time.Second
	}
	if date, err := http.ParseTime(headers.Get("Date")); err == nil && time.Since(date) > age {
		age = time.Since(date)
	}
	headers.Set("Age", strconv.FormatInt(int64(age/time.Second), 10))
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

// cacheableRequest deliberately bypasses requests needing identity-specific,
// range, or revalidation semantics that this shared cache does not implement.
func cacheableRequest(req *http.Request) bool {
	if private, _ := req.Context().Value(privateRequestKey{}).(bool); private {
		return false
	}
	if req.Method != http.MethodGet && req.Method != http.MethodHead {
		return false
	}
	if user := req.Header.Get("X-Authenticated-User"); user != "" && user != "anonymous" {
		return false
	}
	if req.URL.User != nil || (req.Body != nil && req.Body != http.NoBody) {
		return false
	}
	for _, h := range []string{"Authorization", "Proxy-Authorization", "Cookie", "Range", "If-Range", "If-None-Match", "If-Modified-Since", "If-Match", "If-Unmodified-Since"} {
		if req.Header.Get(h) != "" {
			return false
		}
	}
	cc := parseCacheControl(strings.Join(req.Header.Values("Cache-Control"), ","))
	for _, d := range []string{"no-cache", "no-store", "max-age", "min-fresh"} {
		if _, ok := cc[d]; ok {
			return false
		}
	}
	return !strings.EqualFold(req.Header.Get("Pragma"), "no-cache")
}

type failedReader struct{ err error }

func (r failedReader) Read([]byte) (int, error) { return 0, r.err }

// IsCacheable determines if a response is safe to share without revalidation.
func (hc *HTTPCache) IsCacheable(req *http.Request, resp *http.Response) bool {
	if !cacheableRequest(req) || resp == nil || resp.StatusCode != http.StatusOK || strings.HasPrefix(strings.ToLower(resp.Header.Get("Content-Type")), "text/event-stream") {
		return false
	}
	cc := parseCacheControl(strings.Join(resp.Header.Values("Cache-Control"), ","))
	for _, d := range []string{"no-store", "no-cache", "private"} {
		if _, ok := cc[d]; ok {
			return false
		}
	}
	if strings.EqualFold(resp.Header.Get("Pragma"), "no-cache") || resp.Header.Get("Set-Cookie") != "" {
		return false
	}
	// Accept-Encoding is the only negotiated representation in our key.
	for _, vary := range resp.Header.Values("Vary") {
		for _, name := range strings.Split(vary, ",") {
			name = strings.TrimSpace(name)
			if name != "" && !strings.EqualFold(name, "Accept-Encoding") {
				return false
			}
		}
	}
	return hc.CalculateTTL(resp) > 0
}

// CalculateTTL caps freshness and subtracts upstream age. Explicit zero,
// malformed, or expired freshness must never fall back to a positive default.
func (hc *HTTPCache) CalculateTTL(resp *http.Response) time.Duration {
	cc := parseCacheControl(strings.Join(resp.Header.Values("Cache-Control"), ","))
	ttl := hc.config.DefaultTTL
	explicit := false
	for _, name := range []string{"s-maxage", "max-age"} {
		if value, ok := cc[name]; ok {
			seconds, err := strconv.ParseInt(value, 10, 64)
			if err != nil || seconds <= 0 {
				return 0
			}
			// Clamp before multiplication to avoid duration overflow.
			if seconds > int64(hc.config.MaxTTL/time.Second) {
				ttl = hc.config.MaxTTL
			} else {
				ttl = time.Duration(seconds) * time.Second
			}
			explicit = true
			break
		}
	}
	date, dateErr := http.ParseTime(resp.Header.Get("Date"))
	if !explicit && resp.Header.Get("Expires") != "" {
		expires, err := http.ParseTime(resp.Header.Get("Expires"))
		if err != nil {
			return 0
		}
		if dateErr == nil {
			ttl = expires.Sub(date)
		} else {
			ttl = time.Until(expires)
		}
	}
	if ttl > hc.config.MaxTTL {
		ttl = hc.config.MaxTTL
	}
	age := time.Duration(0)
	if dateErr == nil {
		age = time.Since(date)
	}
	if value := resp.Header.Get("Age"); value != "" {
		seconds, err := strconv.ParseInt(value, 10, 64)
		if err != nil || seconds < 0 || seconds > int64(hc.config.MaxTTL/time.Second) {
			return 0
		}
		if upstreamAge := time.Duration(seconds) * time.Second; upstreamAge > age {
			age = upstreamAge
		}
	}
	if age > 0 {
		ttl -= age
	}
	return ttl
}

// GenerateKey preserves escaped paths and raw query ordering, both of which
// origins may distinguish. Host separates virtual hosts on the same upstream.
func (hc *HTTPCache) GenerateKey(req *http.Request) string {
	resource, _ := resourceKey(req)
	data, _ := json.Marshal([]string{req.Method, req.Host, req.Header.Get("Accept-Encoding")})
	variant := sha256.Sum256(data)
	return fmt.Sprintf("cache:http:v3:%s:%x", resource, variant)
}

// Purge invalidates every representation of an absolute URL. Generation
// partitions are bounded; a hash collision safely invalidates extra resources.
func (hc *HTTPCache) Purge(urlStr string) error {
	if hc == nil {
		return nil
	}
	target, err := url.Parse(urlStr)
	if err != nil {
		return err
	}
	if target.Host == "" || target.User != nil || (target.Scheme != "http" && target.Scheme != "https") {
		return fmt.Errorf("purge requires an absolute HTTP(S) URL without credentials")
	}
	return hc.purgeRequest(&http.Request{URL: target, Host: target.Host})
}

// PurgeAll rotates the global namespace, including for in-flight fills.
func (hc *HTTPCache) PurgeAll() error {
	if hc == nil {
		return nil
	}
	if hc.redis != nil {
		if err := hc.redis.bumpEpoch(); err != nil {
			hc.invalidationsFailed.Store(true)
			return err
		}
	}
	hc.generationMu.Lock()
	hc.epoch++
	hc.generationMu.Unlock()
	if hc.memory != nil {
		hc.memory.Clear()
	}
	hc.invalidationsFailed.Store(false)
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
			directives[strings.ToLower(strings.TrimSpace(kv[0]))] = strings.Trim(strings.TrimSpace(kv[1]), `"`)
		} else {
			directives[strings.ToLower(part)] = "true"
		}
	}

	return directives
}
