# Scaling ads-httpproxy to 10,000+ Concurrent Users

Comprehensive architecture for horizontal and vertical scaling using process groups, IPC, threading, and distributed coordination.

## Current Architecture Analysis

**Existing Capabilities**:
- ✅ SO_REUSEPORT for multi-process socket sharing
- ✅ Goroutines for concurrent request handling
- ✅ Connection pooling (ICAP, DNS cache, upstream)
- ✅ HTTP/3 (QUIC) support
- ✅ Listener wrapping (visibility, protocol detection, JA3)
- ❌ No process manager
- ❌ No IPC for state sharing
- ❌ No distributed cache coordination
- ❌ Limited resource control per request

## Target Performance

- **Concurrent Users**: 10,000+
- **Requests/Second**: 50,000+
- **Latency (p95)**: < 50ms
- **Memory per Process**: < 2GB
- **CPU Utilization**: 80%+ efficiency
- **Zero Downtime**: Rolling deployments

---

## Architecture Overview

```
                           ┌─────────────────┐
                           │  Load Balancer  │
                           │   (HAProxy /    │
                           │    Nginx)       │
                           └────────┬────────┘
                                    │
                    ┌───────────────┼───────────────┐
                    │               │               │
             ┌──────▼──────┐ ┌─────▼──────┐ ┌─────▼──────┐
             │  Process 1  │ │ Process 2  │ │ Process N  │
             │  (Worker)   │ │ (Worker)   │ │ (Worker)   │
             └──────┬──────┘ └─────┬──────┘ └─────┬──────┘
                    │               │               │
                    └───────────────┼───────────────┘
                                    │
                            ┌───────▼────────┐
                            │  Shared State   │
                            │  (Redis/NATS)   │
                            └────────────────┘
```

---

## 1. Multi-Process Architecture

###

 1.1 Process Manager (Supervisor)

Create a supervisor process that manages worker processes with:
- Process lifecycle (spawn, monitor, restart)
- Health checks
- Graceful shutdown
- Zero-downtime reload
- CPU affinity binding

**File**: `internal/supervisor/supervisor.go`

```go
type Supervisor struct {
    NumWorkers      int
    Workers         []*Worker
    SharedState     *SharedState
    GracePeriod     time.Duration
    HealthCheckInterval time.Duration
}

type Worker struct {
    PID         int
    Process     *os.Process
    CPU         int           // CPU core affinity
    StartTime   time.Time
    Requests    uint64        // Atomic counter
    Connections uint64
    Status      WorkerStatus
}
```

### 1.2 SO_REUSEPORT Configuration

**Already implemented** in `cmd/proxy/main.go`:
```go
lc.Control = func(network, address string, c syscall.RawConn) error {
    return c.Control(func(fd uintptr) {
        syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEPORT, 1)
    })
}
```

**Benefits**:
- Kernel load balancing across processes
- Each worker accepts connections independently
- No contention on accept() syscall

### 1.3 Worker Process Model

```
Master Process (PID 1)
├── Worker 1 (CPU 0-3)   - Handles 2,500 users
├── Worker 2 (CPU 4-7)   - Handles 2,500 users
├── Worker 3 (CPU 8-11)  - Handles 2,500 users
└── Worker 4 (CPU 12-15) - Handles 2,500 users
```

---

## 2. Inter-Process Communication (IPC)

### 2.1 Unix Domain Sockets

For fast local IPC between workers:

**File**: `internal/ipc/uds.go`

```go
type IPCServer struct {
    SocketPath string
    Listener   net.Listener
    Handlers   map[string]HandlerFunc
}

// Commands:
// - STATS_REQUEST: Get worker stats
// - CACHE_INVALIDATE: Invalidate shared cache entry
// - CONFIG_RELOAD: Reload configuration
// - SHUTDOWN: Graceful shutdown
```

### 2.2 Shared Memory

For low-latency shared state (counters, flags):

**File**: `internal/ipc/shm.go`

```go
type SharedMemory struct {
    Segment    unsafe.Pointer
    Size       int
    Counters   map[string]*int64  // Atomic counters
    Flags      map[string]*int32
}

// Example usage:
// - Request counters (atomic increment)
// - Connection counts
// - Rate limit buckets
// - Circuit breaker states
```

### 2.3 Message Queues

For async communication:

```go
type MessageQueue struct {
    Queue   chan *Message
    Workers int
}

type Message struct {
    Type    MessageType
    Worker  int
    Payload []byte
}
```

---

## 3. Distributed State Management

### 3.1 Redis Integration

**File**: `internal/state/redis.go`

```go
type RedisState struct {
    Client    *redis.Client
    Cluster   *redis.ClusterClient
    Pipeline  redis.Pipeliner
}

// Use cases:
// - Session storage (sticky sessions)
// - Distributed rate limiting
// - Shared cache (URL classifications, threat intel)
// - Metrics aggregation
// - Configuration distribution
```

**Redis Data Structures**:

```redis
# Rate limiting (token bucket)
SETEX rate:user:12345 60 100  # 100 tokens, 60s TTL

# Session storage
HSET session:abc123 user_id 12345 ip 1.2.3.4 expires 1234567890

# Distributed cache
SET cache:threat:example.com '{"score":95,"blocked":true}' EX 3600

# Connection tracking
INCR connections:worker:1
EXPIRE connections:worker:1 60

# Circuit breaker
HINCRBY circuit:upstream:api.example.com failures 1
HSET circuit:upstream:api.example.com state open
```

### 3.2 NATS for Pub/Sub

**File**: `internal/state/nats.go`

```go
type NATSBroker struct {
    Conn    *nats.Conn
    JS      nats.JetStreamContext
}

// Channels:
// - config.reload: Configuration updates
// - metrics.worker: Worker metrics
// - cache.invalidate: Cache invalidation events
// - threat.update: New threat intelligence
```

### 3.3 Consistent Hashing

For distributed cache and session affinity:

```go
type ConsistentHash struct {
    Ring     map[uint32]string
    Nodes    []string
    Replicas int
}

// Use for:
// - Cache key distribution
// - Sticky session routing
// - Worker assignment
```

---

## 4. Threading & Goroutine Management

### 4.1 Goroutine Pool

**File**: `internal/pool/goroutine_pool.go`

```go
type GoroutinePool struct {
    Workers    int
    TaskQueue  chan func()
    WaitGroup  sync.WaitGroup
    Semaphore  chan struct{}
}

// Benefits:
// - Limit goroutine explosion
// - Controlled resource usage
// - Backpressure on overload
```

### 4.2 Worker Pool for Expensive Operations

```go
// ICAP scanning pool
icapPool := NewWorkerPool(50)  // 50 concurrent ICAP requests

// ThreatScript execution pool
scriptPool := NewWorkerPool(100)  // 100 concurrent scripts

// Database query pool
dbPool := NewWorkerPool(200)  // 200 concurrent DB queries
```

### 4.3 Request Context Timeout

```go
// Per-request context with timeout
ctx, cancel := context.WithTimeout(req.Context(), 5*time.Second)
defer cancel()

// Propagate to all sub-operations
resp, err := icapClient.ReqMod(req.WithContext(ctx))
```

---

## 5. Resource Limits & Control

### 5.1 Per-Request Limits

```go
type RequestLimits struct {
    MaxBodySize       int64         // 10MB
    MaxHeaderSize     int           // 8KB
    Timeout           time.Duration // 30s
    MaxGoroutines     int           // 10 per request
    MaxMemory         int64         // 100MB
}
```

### 5.2 Connection Limits

```go
// Per-worker connection limits
http.Server{
    MaxHeaderBytes:    8192,
    ReadTimeout:       30 * time.Second,
    WriteTimeout:      30 * time.Second,
    IdleTimeout:       120 * time.Second,
    MaxConnsPerClient: 100,
}

// Global connection tracking
atomic.AddInt64(&globalConnections, 1)
if atomic.LoadInt64(&globalConnections) > maxConnections {
    // Reject new connections
}
```

### 5.3 Memory Pooling

```go
// Sync.Pool for buffer reuse
var bufferPool = sync.Pool{
    New: func() interface{} {
        return make([]byte, 32*1024)  // 32KB buffers
    },
}

// Usage
buf := bufferPool.Get().([]byte)
defer bufferPool.Put(buf)
```

---

## 6. Deployment Topologies

### 6.1 Single-Machine Multi-Process

```yaml
# 64-core machine, 128GB RAM
workers: 32
worker_config:
  max_connections_per_worker: 500
  goroutines_per_worker: 10000
  memory_per_worker: 2GB
  cpu_affinity: true

total_capacity:
  connections: 16,000
  requests_per_second: 80,000
```

### 6.2 Multi-Machine Cluster

```
                  ┌──────────────┐
                  │  HAProxy LB  │
                  │  (Round Robin│
                  │  /Least Conn)│
                  └───────┬──────┘
                          │
        ┌─────────────────┼─────────────────┐
        │                 │                 │
   ┌────▼─────┐     ┌─────▼────┐     ┌─────▼────┐
   │ Node 1   │     │  Node 2  │     │  Node 3  │
   │ 8 workers│     │ 8 workers│     │ 8 workers│
   └────┬─────┘     └─────┬────┘     └─────┬────┘
        │                 │                 │
        └─────────────────┼─────────────────┘
                          │
                    ┌─────▼──────┐
                    │   Redis    │
                    │  Cluster   │
                    └────────────┘
```

### 6.3 Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ads-httpproxy
spec:
  replicas: 10
  template:
    spec:
      containers:
      - name: proxy
        image: ads-httpproxy:latest
        resources:
          requests:
            cpu: "4"
            memory: "4Gi"
          limits:
            cpu: "8"
            memory: "8Gi"
        env:
        - name: WORKER_PROCESSES
          value: "4"
        - name: MAX_CONNECTIONS
          value: "2000"
```

---

## 7. Monitoring & Observability

### 7.1 Metrics

**File**: `internal/metrics/collector.go`

```go
// Prometheus metrics
var (
    RequestsTotal = promauto.NewCounterVec(
        prometheus.CounterOpts{Name: "proxy_requests_total"},
        []string{"worker", "method", "status"},
    )

    ConnectionsActive = promauto.NewGaugeVec(
        prometheus.GaugeOpts{Name: "proxy_connections_active"},
        []string{"worker"},
    )

    RequestDuration = promauto.NewHistogramVec(
        prometheus.HistogramOpts{
            Name: "proxy_request_duration_seconds",
            Buckets: []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10},
        },
        []string{"worker"},
    )

    GoroutinesActive = promauto.NewGaugeVec(
        prometheus.GaugeOpts{Name: "proxy_goroutines"},
        []string{"worker"},
    )

    MemoryUsage = promauto.NewGaugeVec(
        prometheus.GaugeOpts{Name: "proxy_memory_bytes"},
        []string{"worker"},
    )
)
```

### 7.2 Health Checks

```go
// Per-worker health
GET /health
{
  "worker_id": 1,
  "status": "healthy",
  "connections": 450,
  "goroutines": 8500,
  "memory_mb": 1850,
  "cpu_percent": 75.5,
  "uptime_seconds": 86400
}

// Aggregate health
GET /health/aggregate
{
  "total_workers": 8,
  "healthy_workers": 8,
  "total_connections": 3200,
  "requests_per_second": 12450,
  "avg_latency_ms": 15.3
}
```

### 7.3 Distributed Tracing

```go
import "go.opentelemetry.io/otel"

// Trace request through:
// - Load balancer
// - Worker process
// - Threat intelligence
// - ICAP scanning
// - Upstream request
```

---

## 8. Performance Optimizations

### 8.1 Zero-Copy Operations

```go
// Use io.Copy for body streaming (zero-copy)
io.Copy(dst, src)

// Use sendfile() for large files
file.WriteTo(conn)  // Uses sendfile() internally

// Avoid unnecessary allocations
var buf [8192]byte  // Stack allocation
io.CopyBuffer(dst, src, buf[:])
```

### 8.2 Connection Pooling

```go
// HTTP client pool per upstream
var upstreamPools = map[string]*http.Transport{
    "api.example.com": {
        MaxIdleConns:        100,
        MaxIdleConnsPerHost: 100,
        MaxConnsPerHost:     200,
        IdleConnTimeout:     90 * time.Second,
    },
}

// ICAP connection pool (already implemented)
icapClient.connPool  // 10 pooled connections

// DNS cache connection pool
dnsCache.connPool  // gRPC connection pool
```

### 8.3 CPU Affinity

```go
// Pin worker to CPU cores
func setAffinity(worker int, cpus []int) {
    runtime.LockOSThread()
    defer runtime.UnlockOSThread()

    // Use runtime.SetCPUCores() or syscall
    // Linux: sched_setaffinity()
}
```

### 8.4 Memory Tuning

```go
// GOGC tuning
os.Setenv("GOGC", "200")  // Run GC less frequently

// GOMEMLIMIT (Go 1.19+)
os.Setenv("GOMEMLIMIT", "2GiB")  // Soft memory limit

// Pre-allocate large slices
buf := make([]byte, 0, 1024*1024)  // Pre-allocate 1MB capacity
```

---

## 9. Benchmarking Results (Projected)

### Single Worker (8 cores, 16GB RAM)

| Metric | Value |
|--------|-------|
| Max Connections | 2,000 |
| Requests/Second | 10,000 |
| Avg Latency | 10ms |
| P95 Latency | 25ms |
| P99 Latency | 50ms |
| Memory Usage | 1.5GB |
| CPU Usage | 85% |

### 8 Workers (64 cores, 128GB RAM)

| Metric | Value |
|--------|-------|
| Max Connections | 16,000 |
| Requests/Second | 80,000 |
| Avg Latency | 15ms |
| P95 Latency | 35ms |
| P99 Latency | 75ms |
| Total Memory | 12GB |
| Avg CPU/Core | 80% |

### 10-Node Cluster (640 cores, 1.28TB RAM)

| Metric | Value |
|--------|-------|
| Max Connections | 160,000 |
| Requests/Second | 800,000 |
| Avg Latency | 20ms |
| P95 Latency | 45ms |
| P99 Latency | 100ms |
| Total Memory | 120GB |

---

## 10. Implementation Roadmap

### Phase 1: Process Manager (Week 1)
- [ ] Supervisor process with worker management
- [ ] Graceful shutdown/reload
- [ ] Health monitoring
- [ ] CPU affinity

### Phase 2: IPC & Shared State (Week 2)
- [ ] Unix domain socket IPC
- [ ] Shared memory for counters
- [ ] Redis integration
- [ ] NATS pub/sub

### Phase 3: Resource Management (Week 3)
- [ ] Goroutine pools
- [ ] Connection limits
- [ ] Memory pooling
- [ ] Request timeouts

### Phase 4: Metrics & Observability (Week 4)
- [ ] Per-worker Prometheus metrics
- [ ] Distributed tracing
- [ ] Aggregate health endpoints
- [ ] Grafana dashboards

### Phase 5: Testing & Optimization (Week 5-6)
- [ ] Load testing (10k+ users)
- [ ] Profiling (CPU, memory, goroutines)
- [ ] Optimization based on bottlenecks
- [ ] Documentation

---

## 11. Load Testing Strategy

### Tools

1. **wrk2** - HTTP benchmarking
2. **vegeta** - HTTP load testing
3. **hey** - HTTP load generator
4. **k6** - Modern load testing

### Test Scenarios

```bash
# Scenario 1: Sustained load
wrk2 -t 32 -c 1000 -d 300s -R 10000 --latency http://proxy:8080

# Scenario 2: Burst traffic
vegeta attack -rate=0 -max-workers=1000 -duration=60s | vegeta report

# Scenario 3: Mixed workload
k6 run --vus 10000 --duration 10m mixed_workload.js
```

---

## 12. Configuration Example

```yaml
# config.yaml
scaling:
  mode: "multi-process"  # single, multi-process, cluster

  supervisor:
    num_workers: 8
    cpu_affinity: true
    graceful_shutdown_timeout: 30s
    worker_restart_delay: 5s

  worker:
    max_connections: 2000
    max_goroutines: 10000
    memory_limit: "2GiB"
    request_timeout: 30s
    idle_timeout: 120s

  ipc:
    unix_socket: "/tmp/ads-proxy-ipc.sock"
    shared_memory_size: "100MB"

  state:
    backend: "redis"  # redis, nats, etcd
    redis:
      addr: "localhost:6379"
      cluster: true
      pool_size: 100

  pools:
    goroutine_pool_size: 10000
    icap_pool_size: 50
    script_pool_size: 100
    db_pool_size: 200

  limits:
    max_body_size: "10MB"
    max_header_size: "8KB"
    max_request_duration: "30s"
    max_memory_per_request: "100MB"
```

---

## Conclusion

This architecture provides:
- **Linear scalability**: Add more workers/nodes for more capacity
- **High availability**: Worker failures don't affect others
- **Resource efficiency**: 80%+ CPU utilization, controlled memory
- **Low latency**: < 50ms P95 with proper tuning
- **Observability**: Full metrics, tracing, and health checks

Ready to handle 10,000+ concurrent users with sub-50ms latency.
