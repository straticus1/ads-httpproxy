# HTTP Caching Strategy for ads-httpproxy

## Current State Analysis

### Existing Infrastructure ✅
- **Redis Integration**: `internal/cache/redis.go` - Basic Get/Set operations
- **Peering Support**: `internal/peering/manager.go` - ICP/HTCP distributed cache queries
- **Configuration**: Redis config exists in `config.RedisConfig`

### Current Limitations ❌
- Cache is created but **not used** for HTTP responses
- No HTTP cache headers respected (Cache-Control, Expires, ETag, Last-Modified)
- No cache key generation strategy
- No conditional request support (304 Not Modified)
- No cache eviction policy documented
- No cache warming or preloading

---

## Recommendation: **Use Redis for Caching**

### Why Redis Over Custom Implementation?

| Aspect | Redis | Custom In-Memory |
|--------|-------|------------------|
| **Distributed** | ✅ Shared across multiple proxy instances | ❌ Per-instance only |
| **Persistence** | ✅ Survives proxy restart | ❌ Lost on restart |
| **Memory Management** | ✅ Built-in eviction policies (LRU, LFU) | ⚠️ Must implement manually |
| **Performance** | ✅ ~1ms latency for local Redis | ✅ ~0.1ms (but limited capacity) |
| **Scalability** | ✅ Redis Cluster for TB-scale | ❌ Limited by instance RAM |
| **Monitoring** | ✅ redis-cli, RedisInsight, Prometheus | ⚠️ Must build custom |
| **Cost** | ⚠️ Requires Redis infrastructure | ✅ No additional infrastructure |

**Verdict**: Use Redis as primary cache, with optional in-memory L1 cache for hot objects.

---

## Architecture: Two-Tier Caching

### Tier 1: In-Memory LRU Cache (Optional)
- **Purpose**: Hot object cache for sub-millisecond access
- **Size**: 100MB - 1GB per instance
- **TTL**: 60 seconds max
- **Eviction**: LRU (Least Recently Used)
- **Hit Rate Target**: 20-30% of requests

### Tier 2: Redis Cache (Primary)
- **Purpose**: Shared, persistent cache across all instances
- **Size**: 10GB - 100GB+ (configurable)
- **TTL**: Respects HTTP cache headers (max 24h default)
- **Eviction**: volatile-lru (Redis config)
- **Hit Rate Target**: 60-80% of cacheable requests

### Request Flow

```
┌─────────┐
│ Client  │
└────┬────┘
     │ GET /page.html
     ▼
┌─────────────────┐
│ ads-httpproxy   │
└────┬────────────┘
     │
     ├─► L1 Cache (memory) ───► HIT? ──► Return (0.1ms)
     │                           │
     │                           │ MISS
     │                           ▼
     ├─► L2 Cache (Redis) ───► HIT? ──► Store in L1 ──► Return (1ms)
     │                           │
     │                           │ MISS
     │                           ▼
     └─► Origin Server ────────► Store in L2+L1 ──► Return (50-500ms)
```

---

## Implementation Plan

### Phase 1: HTTP Response Caching (Essential)

**What to Cache:**
- ✅ Static assets (images, CSS, JS, fonts)
- ✅ API responses with Cache-Control headers
- ✅ HTML pages with explicit caching
- ❌ POST/PUT/DELETE requests
- ❌ Authenticated requests (unless explicitly safe)
- ❌ Responses with Set-Cookie headers
- ❌ Dynamic content without cache headers

**Cache Key Strategy:**
```
cache:http:{method}:{scheme}://{host}{path}?{sorted_query}:{accept-encoding}
```

Examples:
```
cache:http:GET:https://example.com/api/user?id=123:gzip
cache:http:GET:https://cdn.example.com/style.css:br
```

**Respect HTTP Headers:**
```go
// Cacheable if:
- Cache-Control: public, max-age=3600
- Cache-Control: s-maxage=7200 (proxy-specific)
- Expires: Thu, 01 Dec 2026 16:00:00 GMT

// NOT cacheable if:
- Cache-Control: private
- Cache-Control: no-store
- Cache-Control: no-cache (revalidate only)
- Pragma: no-cache
- Authorization header present (unless Cache-Control: public)
```

### Phase 2: Conditional Requests (304 Not Modified)

Support `If-Modified-Since` and `If-None-Match`:

```go
// Store with response:
- ETag
- Last-Modified

// On cache HIT:
if request.Header["If-None-Match"] == cached.ETag {
    return 304 Not Modified
}
if request.Header["If-Modified-Since"] >= cached.LastModified {
    return 304 Not Modified
}
```

**Bandwidth Savings**: 90%+ for unchanged resources

### Phase 3: Cache Warming & Preloading

```yaml
cache:
  enabled: true
  warming:
    enabled: true
    urls:
      - https://example.com/
      - https://example.com/api/popular
    interval: 5m  # Refresh every 5 minutes
```

### Phase 4: Intelligent Eviction

**Eviction Policies:**
1. **Time-based**: Respect max-age
2. **Size-based**: LRU when Redis hits memory limit
3. **Pattern-based**: Purge cache for specific URL patterns
4. **Tag-based**: Invalidate related resources

```yaml
cache:
  max_memory: 10GB
  eviction_policy: volatile-lru
  default_ttl: 3600        # 1 hour
  max_ttl: 86400           # 24 hours
```

---

## Configuration Structure

```yaml
addr: ":8080"

# Redis Configuration
redis:
  enabled: true
  addr: "localhost:6379"
  password: ""
  db: 0

# HTTP Caching
cache:
  enabled: true

  # L1 In-Memory Cache (optional)
  memory:
    enabled: true
    max_size_mb: 500
    max_ttl: 60  # seconds

  # L2 Redis Cache
  redis:
    enabled: true
    max_memory_gb: 10
    eviction_policy: "volatile-lru"
    default_ttl: 3600     # 1 hour
    max_ttl: 86400        # 24 hours
    min_size_bytes: 1024  # Don't cache responses < 1KB
    max_size_bytes: 10485760  # Don't cache responses > 10MB

  # Cache Rules
  rules:
    # Static assets - aggressive caching
    - pattern: "\\.(jpg|jpeg|png|gif|ico|css|js|woff2|ttf|svg)$"
      ttl: 86400  # 24 hours

    # API responses - short TTL
    - pattern: "^/api/"
      ttl: 300    # 5 minutes

    # HTML pages - moderate caching
    - pattern: "\\.html?$"
      ttl: 1800   # 30 minutes

  # Bypass Rules
  bypass:
    - pattern: "^/admin/"
    - pattern: "\\?nocache=1"
    - user_agents:
        - "bot"
        - "crawler"

  # Cache Warming
  warming:
    enabled: true
    urls:
      - https://example.com/
      - https://example.com/popular-page
    interval: 300  # seconds

  # Purge API
  purge:
    enabled: true
    auth_token: "secret"  # PURGE /cache/https://example.com/page
```

---

## Code Implementation

### 1. Enhanced Cache Manager

```go
// internal/cache/manager.go
type CacheManager struct {
    redis      *redis.Client
    memory     *MemoryCache  // L1 cache
    config     *CacheConfig
    stats      *CacheStats
}

type CachedResponse struct {
    StatusCode  int
    Headers     http.Header
    Body        []byte
    ETag        string
    LastModified time.Time
    CachedAt    time.Time
    TTL         time.Duration
}

func (cm *CacheManager) Get(req *http.Request) (*CachedResponse, bool) {
    key := cm.generateKey(req)

    // L1 Check
    if cm.memory != nil {
        if resp, ok := cm.memory.Get(key); ok {
            cm.stats.L1Hits++
            return resp, true
        }
    }

    // L2 Check
    data, ok := cm.redis.Get(key)
    if !ok {
        cm.stats.Misses++
        return nil, false
    }

    resp := &CachedResponse{}
    if err := json.Unmarshal(data, resp); err != nil {
        return nil, false
    }

    // Promote to L1
    if cm.memory != nil {
        cm.memory.Set(key, resp, 60*time.Second)
    }

    cm.stats.L2Hits++
    return resp, true
}

func (cm *CacheManager) Set(req *http.Request, resp *http.Response) {
    if !cm.isCacheable(req, resp) {
        return
    }

    key := cm.generateKey(req)
    ttl := cm.calculateTTL(resp)

    cached := &CachedResponse{
        StatusCode:   resp.StatusCode,
        Headers:      resp.Header,
        Body:         readBody(resp),
        ETag:         resp.Header.Get("ETag"),
        LastModified: parseTime(resp.Header.Get("Last-Modified")),
        CachedAt:     time.Now(),
        TTL:          ttl,
    }

    data, _ := json.Marshal(cached)

    // Store in both tiers
    cm.redis.Set(key, data, ttl)
    if cm.memory != nil {
        cm.memory.Set(key, cached, min(ttl, 60*time.Second))
    }
}

func (cm *CacheManager) isCacheable(req *http.Request, resp *http.Response) bool {
    // Only GET and HEAD
    if req.Method != "GET" && req.Method != "HEAD" {
        return false
    }

    // Check Cache-Control
    cc := resp.Header.Get("Cache-Control")
    if strings.Contains(cc, "no-store") || strings.Contains(cc, "private") {
        return false
    }

    // No Set-Cookie
    if resp.Header.Get("Set-Cookie") != "" {
        return false
    }

    // 2xx or 3xx responses only
    if resp.StatusCode < 200 || resp.StatusCode >= 400 {
        return false
    }

    // Size limits
    if resp.ContentLength > cm.config.MaxSizeBytes {
        return false
    }

    return true
}

func (cm *CacheManager) generateKey(req *http.Request) string {
    // Sort query parameters for consistent keys
    query := req.URL.Query()
    var keys []string
    for k := range query {
        keys = append(keys, k)
    }
    sort.Strings(keys)

    var sortedQuery string
    for _, k := range keys {
        sortedQuery += k + "=" + query.Get(k) + "&"
    }

    encoding := req.Header.Get("Accept-Encoding")

    return fmt.Sprintf("cache:http:%s:%s://%s%s?%s:%s",
        req.Method,
        req.URL.Scheme,
        req.URL.Host,
        req.URL.Path,
        sortedQuery,
        encoding,
    )
}
```

### 2. Middleware Integration

```go
// internal/proxy/middleware.go
func (s *Server) middlewareCache(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
    if s.cache == nil {
        return req, nil
    }

    // Check cache
    cached, ok := s.cache.Get(req)
    if !ok {
        // Cache miss - continue to origin
        return req, nil
    }

    // Check conditional requests
    if etag := req.Header.Get("If-None-Match"); etag != "" && etag == cached.ETag {
        return req, &http.Response{
            StatusCode: 304,
            Header:     http.Header{"ETag": []string{cached.ETag}},
        }
    }

    // Cache HIT - return cached response
    resp := &http.Response{
        StatusCode: cached.StatusCode,
        Header:     cached.Headers.Clone(),
        Body:       ioutil.NopCloser(bytes.NewReader(cached.Body)),
        Request:    req,
    }

    resp.Header.Set("X-Cache", "HIT")
    resp.Header.Set("Age", fmt.Sprintf("%d", int(time.Since(cached.CachedAt).Seconds())))

    return nil, resp
}

func (s *Server) middlewareRespCache(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
    if s.cache == nil {
        return resp
    }

    // Store response in cache
    s.cache.Set(ctx.Req, resp)

    resp.Header.Set("X-Cache", "MISS")
    return resp
}
```

---

## Performance Expectations

### Cache Hit Rates

| Content Type | Expected Hit Rate |
|--------------|-------------------|
| Static assets (CSS, JS, images) | 90-95% |
| API responses | 40-60% |
| HTML pages | 50-70% |
| Overall | 60-80% |

### Latency Improvements

| Scenario | Without Cache | With L1 | With L2 (Redis) |
|----------|---------------|---------|-----------------|
| Static asset | 50-200ms | **0.1ms** | 1ms |
| API response | 100-500ms | **0.1ms** | 1-2ms |
| HTML page | 200-1000ms | **0.1ms** | 1-2ms |

### Bandwidth Savings

- **304 Not Modified**: 90% bandwidth reduction
- **Cached responses**: 100% bandwidth reduction (origin)
- **Expected overall**: 60-80% reduction in origin traffic

---

## Monitoring & Metrics

```go
type CacheStats struct {
    L1Hits       uint64
    L2Hits       uint64
    Misses       uint64
    Errors       uint64
    BytesSaved   uint64

    HitRate      float64  // (L1+L2)/(L1+L2+Misses)
    AvgL1Latency time.Duration
    AvgL2Latency time.Duration
}

// Expose via API
GET /api/cache/stats
{
  "l1_hits": 12500,
  "l2_hits": 8300,
  "misses": 4200,
  "hit_rate": 0.83,
  "avg_l1_latency_ms": 0.08,
  "avg_l2_latency_ms": 1.2,
  "bytes_saved_gb": 45.3
}
```

### Redis Monitoring

```bash
# Redis stats
redis-cli INFO stats

# Cache size
redis-cli DBSIZE

# Memory usage
redis-cli INFO memory

# Eviction stats
redis-cli INFO stats | grep evicted
```

---

## Cache Invalidation Strategies

### 1. Time-based (Automatic)
- Respects `Cache-Control: max-age`
- Default TTL from config
- Redis automatically evicts expired keys

### 2. Manual Purge API
```bash
# Purge single URL
curl -X PURGE http://proxy:9090/cache/https://example.com/page

# Purge pattern
curl -X POST http://proxy:9090/api/cache/purge \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"pattern": "^https://example.com/api/.*"}'

# Purge all
curl -X DELETE http://proxy:9090/api/cache/all \
  -H "Authorization: Bearer $TOKEN"
```

### 3. Event-driven (Webhooks)
```yaml
cache:
  webhooks:
    - url: http://proxy:9090/api/cache/purge
      events: ["content.updated", "product.changed"]
```

### 4. Header-based
```http
Cache-Control: max-age=0, must-revalidate
```

---

## Security Considerations

### What NOT to Cache

- ❌ Responses with `Authorization` header (unless `Cache-Control: public`)
- ❌ POST/PUT/DELETE requests
- ❌ Responses with `Set-Cookie`
- ❌ Admin panels (`/admin/*`)
- ❌ User-specific content
- ❌ CSRF tokens
- ❌ Session data

### Cache Poisoning Prevention

```go
// Only cache safe methods
if req.Method != "GET" && req.Method != "HEAD" {
    return false
}

// Sanitize Vary header
varyHeaders := []string{"Accept-Encoding"}
key := generateKey(req, varyHeaders)

// Don't cache query parameters that affect auth
if req.URL.Query().Get("token") != "" {
    return false
}
```

---

## Deployment Checklist

### Redis Setup

```bash
# Install Redis
apt-get install redis-server

# Configure
vim /etc/redis/redis.conf
```

```conf
# /etc/redis/redis.conf
maxmemory 10gb
maxmemory-policy volatile-lru
save ""  # Disable RDB persistence (cache only)
appendonly no  # Disable AOF (cache only)

# Performance
tcp-backlog 511
timeout 0
tcp-keepalive 300
```

### ads-httpproxy Configuration

```yaml
redis:
  enabled: true
  addr: "localhost:6379"
  password: ""
  db: 0

cache:
  enabled: true
  memory:
    enabled: true
    max_size_mb: 500
  redis:
    max_memory_gb: 10
    default_ttl: 3600
```

### Monitoring

```bash
# Prometheus metrics
curl http://proxy:9090/metrics | grep cache

# Redis monitoring
redis-cli MONITOR

# Cache stats
curl http://proxy:9090/api/cache/stats
```

---

## Alternatives Considered

### 1. Varnish Cache
- **Pros**: Industry standard, extremely fast
- **Cons**: Additional component, complex VCL configuration
- **Verdict**: Overkill for this use case

### 2. Nginx caching
- **Pros**: Fast, simple
- **Cons**: Not distributed, requires Nginx in front
- **Verdict**: Doesn't fit proxy architecture

### 3. Custom in-memory only
- **Pros**: Simplest, fastest
- **Cons**: Not distributed, not persistent
- **Verdict**: Not suitable for production

### 4. Memcached
- **Pros**: Fast, simple
- **Cons**: No persistence, less feature-rich than Redis
- **Verdict**: Redis is better for this use case

---

## Conclusion

**Recommended Approach**:
- **Primary**: Redis for distributed, persistent caching
- **Optional**: In-memory L1 cache for hot objects
- **Implementation**: Phase 1 (basic caching) in next sprint

**Expected Benefits**:
- 60-80% cache hit rate
- 90%+ latency reduction for cached content
- 60-80% reduction in origin traffic
- Horizontal scalability across proxy instances

**Next Steps**:
1. Implement enhanced CacheManager (Phase 1)
2. Add middleware integration
3. Deploy Redis cluster
4. Monitor and tune cache policies
