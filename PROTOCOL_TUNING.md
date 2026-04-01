# Protocol Tuning Guide

Complete guide to HTTP/HTTPS/HTTP2/HTTP3(QUIC) protocol tuning and system-level optimizations for ads-httpproxy.

## Overview

The proxy supports extensive tuning for:
- **HTTP/1.1** - Connection pooling, keep-alive, timeouts
- **HTTP/2** - Stream limits, frame sizes, flow control
- **HTTP/3 (QUIC)** - UDP tuning, congestion control, 0-RTT
- **TLS** - Cipher suites, session resumption, OCSP stapling
- **TCP** - Socket buffers, congestion control, backlog
- **System (sysctl)** - Kernel network stack tuning

## Current Tuning Options

### HTTP Transport (upstream.go:161-166)

```go
&http.Transport{
    DialContext:     dialFunc,
    MaxIdleConns:    100,           // Total idle connections across all hosts
    IdleConnTimeout: 90 * time.Second,  // How long idle connections stay open
}
```

**Limited!** Only basic settings. Need expansion.

### QUIC/HTTP3 Support (server.go:626)

```go
h3Server := &http3.Server{
    Handler: s.httpServer.Handler,
}
```

**Minimal!** Uses defaults. No tuning exposed.

## Recommended Tuning Configuration

### Add to config.yaml

```yaml
# Protocol Tuning Configuration
tuning:
  # HTTP/1.1 and HTTP/2 Transport Settings
  http:
    # Connection Pooling
    max_idle_conns: 1000              # Total idle connections (default: 100)
    max_idle_conns_per_host: 100      # Per-host idle connections (default: 2)
    max_conns_per_host: 0             # Max total per host (0 = unlimited)

    # Timeouts
    idle_conn_timeout: 90s            # How long idle connections stay open
    response_header_timeout: 30s      # Wait for response headers
    expect_continue_timeout: 1s       # Wait for 100-continue response
    tls_handshake_timeout: 10s        # TLS handshake timeout
    dial_timeout: 30s                 # TCP connection timeout
    keep_alive: 30s                   # TCP keep-alive interval

    # HTTP/2 Specific
    http2:
      enabled: true                   # Enable HTTP/2 (default: true)
      max_concurrent_streams: 250     # Max concurrent streams per connection
      max_header_list_size: 262144    # 256KB max header size
      initial_window_size: 1048576    # 1MB initial flow control window
      max_frame_size: 16384           # 16KB max frame size
      max_read_frame_size: 1048576    # 1MB max read frame
      ping_timeout: 15s               # PING frame timeout
      read_idle_timeout: 0            # Connection read idle timeout (0 = no timeout)
      write_byte_timeout: 0           # Per-byte write timeout

    # Request/Response Limits
    max_response_header_bytes: 1048576  # 1MB max response headers
    write_buffer_size: 4096             # Socket write buffer
    read_buffer_size: 4096              # Socket read buffer

    # Connection Behavior
    disable_keep_alives: false        # Disable HTTP keep-alive
    disable_compression: false        # Disable gzip/deflate compression
    force_attempt_http2: true         # Always try HTTP/2 first

  # QUIC/HTTP3 Settings
  quic:
    enabled: true                     # Enable QUIC/HTTP3
    max_incoming_streams: 1000        # Max concurrent streams
    max_incoming_uni_streams: 1000    # Max unidirectional streams
    initial_stream_receive_window: 524288   # 512KB per-stream window
    max_stream_receive_window: 6291456      # 6MB max per-stream window
    initial_connection_receive_window: 1048576  # 1MB connection window
    max_connection_receive_window: 15728640     # 15MB max connection window
    max_idle_timeout: 30s             # Idle connection timeout
    handshake_idle_timeout: 10s       # Handshake timeout
    keep_alive_period: 10s            # Keep-alive PING interval
    disable_path_mtu_discovery: false # MTU discovery
    enable_datagram: false            # Enable QUIC datagrams
    max_datagram_frame_size: 1350     # Max datagram size

  # TLS Settings
  tls:
    min_version: "1.2"                # Minimum TLS version (1.0, 1.1, 1.2, 1.3)
    max_version: "1.3"                # Maximum TLS version
    cipher_suites:                    # Allowed cipher suites (empty = Go defaults)
      - "TLS_AES_128_GCM_SHA256"
      - "TLS_AES_256_GCM_SHA384"
      - "TLS_CHACHA20_POLY1305_SHA256"
    prefer_server_cipher_suites: false
    session_cache_size: 65536         # TLS session cache entries
    renegotiation: "never"            # never, once, freely

    # Certificate Settings
    verify_peer_certificate: true
    insecure_skip_verify: false       # Skip cert verification (DANGEROUS)

    # Performance
    session_tickets_disabled: false   # Enable session tickets (faster reconnects)
    dynamic_record_sizing_disabled: false  # Dynamic TLS record sizing

  # TCP Socket Settings
  tcp:
    send_buffer_size: 4194304         # 4MB SO_SNDBUF
    recv_buffer_size: 4194304         # 4MB SO_RCVBUF
    no_delay: true                    # Disable Nagle's algorithm (TCP_NODELAY)
    keep_alive: true                  # Enable TCP keep-alive
    keep_alive_interval: 30s          # Keep-alive probe interval
    keep_alive_count: 9               # Keep-alive probe count before close
    linger_timeout: 0                 # SO_LINGER (0 = disabled)
    reuse_port: false                 # SO_REUSEPORT (Linux 3.9+)
    fast_open: false                  # TCP Fast Open (TFO)
    defer_accept: false               # TCP_DEFER_ACCEPT (Linux)
    quick_ack: false                  # TCP_QUICKACK (Linux)
    congestion_control: "bbr"         # TCP congestion control algorithm
```

## System-Level Tuning (sysctl)

### Linux Kernel Network Stack Optimization

Create `/etc/sysctl.d/99-proxy-tuning.conf`:

```bash
# ===================================================================
# TCP/IP Stack Tuning for HTTP/HTTPS/QUIC Proxy
# ===================================================================

# ---------------------------
# Connection Tracking
# ---------------------------
# Increase connection tracking table size for high-volume proxy
net.netfilter.nf_conntrack_max = 1048576
net.netfilter.nf_conntrack_tcp_timeout_established = 600
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 30

# ---------------------------
# TCP Settings
# ---------------------------
# Enable TCP Fast Open (TFO) for faster connection establishment
net.ipv4.tcp_fastopen = 3                    # 1=client, 2=server, 3=both

# TCP window scaling (essential for high-latency, high-bandwidth)
net.ipv4.tcp_window_scaling = 1

# Increase TCP buffer sizes for high throughput
net.ipv4.tcp_rmem = 4096 87380 16777216      # min default max (16MB)
net.ipv4.tcp_wmem = 4096 65536 16777216      # min default max (16MB)
net.core.rmem_max = 16777216                 # Max receive buffer (16MB)
net.core.wmem_max = 16777216                 # Max send buffer (16MB)
net.core.rmem_default = 262144               # Default receive (256KB)
net.core.wmem_default = 262144               # Default send (256KB)

# TCP congestion control - BBR for optimal throughput
net.ipv4.tcp_congestion_control = bbr
net.core.default_qdisc = fq                  # Fair Queue required for BBR

# TCP connection handling
net.ipv4.tcp_max_syn_backlog = 8192          # SYN queue size
net.core.somaxconn = 4096                    # Listen backlog
net.core.netdev_max_backlog = 5000           # Network device backlog

# TIME_WAIT socket reuse (safe for proxy)
net.ipv4.tcp_tw_reuse = 1                    # Reuse TIME_WAIT sockets
# Note: tcp_tw_recycle removed in Linux 4.12+ (unsafe with NAT)

# Reduce TIME_WAIT duration
net.ipv4.tcp_fin_timeout = 30                # Seconds (default: 60)

# TCP keepalive settings (detect dead connections)
net.ipv4.tcp_keepalive_time = 300            # Start probes after 5 min idle
net.ipv4.tcp_keepalive_intvl = 30            # Probe interval (seconds)
net.ipv4.tcp_keepalive_probes = 9            # Probes before giving up

# TCP retries
net.ipv4.tcp_syn_retries = 3                 # SYN retries (reduce from 6)
net.ipv4.tcp_synack_retries = 3              # SYN-ACK retries

# Enable TCP SACK (Selective ACK) for better recovery
net.ipv4.tcp_sack = 1

# Enable TCP timestamps (RTT measurement)
net.ipv4.tcp_timestamps = 1

# Disable TCP slow start after idle (controversial)
net.ipv4.tcp_slow_start_after_idle = 0

# MTU probing (discover optimal packet size)
net.ipv4.tcp_mtu_probing = 1

# ---------------------------
# UDP Settings (for QUIC/HTTP3)
# ---------------------------
# Increase UDP buffer sizes for QUIC
net.core.rmem_max = 26214400                 # 25MB UDP receive buffer
net.core.wmem_max = 26214400                 # 25MB UDP send buffer
net.ipv4.udp_rmem_min = 4096
net.ipv4.udp_wmem_min = 4096

# ---------------------------
# IP Settings
# ---------------------------
# Local port range for outbound connections
net.ipv4.ip_local_port_range = 10000 65535

# Increase number of file descriptors
fs.file-max = 2097152

# Increase inotify limits (if monitoring config files)
fs.inotify.max_user_watches = 524288

# ---------------------------
# Network Core Settings
# ---------------------------
# Increase network device receive queue
net.core.netdev_budget = 600                 # Packets per NAPI poll
net.core.netdev_budget_usecs = 8000          # Microseconds per poll

# ---------------------------
# IPv6 (if using IPv6)
# ---------------------------
net.ipv6.conf.all.forwarding = 1
net.ipv6.conf.default.forwarding = 1

# ---------------------------
# Security (if needed)
# ---------------------------
# Disable IP forwarding (if proxy doesn't need it)
# net.ipv4.ip_forward = 0

# SYN flood protection
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 8192

# Reverse path filtering
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Disable ICMP redirects (security)
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Disable source routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
```

**Apply settings**:
```bash
sudo sysctl -p /etc/sysctl.d/99-proxy-tuning.conf
```

**Verify**:
```bash
sysctl net.ipv4.tcp_congestion_control
sysctl net.core.rmem_max
sysctl net.ipv4.tcp_fastopen
```

### macOS Kernel Tuning

```bash
# Increase socket buffer sizes
sudo sysctl -w kern.ipc.maxsockbuf=16777216
sudo sysctl -w net.inet.tcp.sendspace=1048576
sudo sysctl -w net.inet.tcp.recvspace=1048576

# TCP Fast Open
sudo sysctl -w net.inet.tcp.fastopen=3

# Increase connection backlog
sudo sysctl -w kern.ipc.somaxconn=4096

# Port range
sudo sysctl -w net.inet.ip.portrange.first=10000
sudo sysctl -w net.inet.ip.portrange.last=65535

# File descriptors
sudo sysctl -w kern.maxfiles=1048576
sudo sysctl -w kern.maxfilesperproc=1048576

# TIME_WAIT
sudo sysctl -w net.inet.tcp.msl=15000  # 15 seconds
```

### FreeBSD Kernel Tuning

```bash
# /etc/sysctl.conf
kern.ipc.somaxconn=4096
kern.ipc.maxsockbuf=16777216

net.inet.tcp.sendspace=1048576
net.inet.tcp.recvspace=1048576
net.inet.tcp.sendbuf_max=16777216
net.inet.tcp.recvbuf_max=16777216

net.inet.tcp.fastopen.server_enable=1
net.inet.tcp.fastopen.client_enable=1

net.inet.ip.portrange.first=10000
net.inet.ip.portrange.last=65535

net.inet.tcp.msl=15000
```

## Protocol-Specific Optimizations

### HTTP/1.1 Optimization

**Connection Pooling**:
```yaml
tuning:
  http:
    max_idle_conns: 1000          # High for many upstreams
    max_idle_conns_per_host: 100  # Balance reuse vs memory
    idle_conn_timeout: 90s        # Match server keep-alive
```

**When to use**:
- Large number of upstream servers
- High request rate
- Low latency requirements

**Trade-offs**:
- Memory: ~10KB per idle connection
- File descriptors: One per connection

### HTTP/2 Optimization

**Stream Limits**:
```yaml
tuning:
  http:
    http2:
      max_concurrent_streams: 250      # Higher = more parallelism
      initial_window_size: 1048576     # 1MB for high throughput
      max_header_list_size: 262144     # 256KB for large headers
```

**When to use**:
- Modern backends supporting HTTP/2
- Many small requests (APIs, microservices)
- Header-heavy traffic

**Benefits**:
- Multiplexing (one TCP connection)
- Header compression (HPACK)
- Server push (if backend supports)

### HTTP/3 (QUIC) Optimization

**UDP Buffers**:
```yaml
tuning:
  quic:
    max_incoming_streams: 1000
    initial_stream_receive_window: 524288      # 512KB
    initial_connection_receive_window: 1048576  # 1MB
```

**System (sysctl)**:
```bash
net.core.rmem_max = 26214400   # 25MB for QUIC
net.core.wmem_max = 26214400
```

**When to use**:
- High packet loss environments
- Mobile clients (connection migration)
- Latency-sensitive applications

**Benefits**:
- 0-RTT connection resumption
- No head-of-line blocking
- Connection migration (IP change)

### TLS Optimization

**Session Resumption**:
```yaml
tuning:
  tls:
    session_cache_size: 65536           # 64K sessions
    session_tickets_disabled: false     # Enable tickets
```

**Cipher Selection** (performance order):
```yaml
tuning:
  tls:
    cipher_suites:
      - "TLS_AES_128_GCM_SHA256"        # Fastest (AES-NI)
      - "TLS_CHACHA20_POLY1305_SHA256"  # Fastest (no AES-NI)
      - "TLS_AES_256_GCM_SHA384"        # Secure but slower
```

**Benefits**:
- AES-128-GCM: ~3x faster with AES-NI CPU
- Session tickets: ~50% faster reconnect
- TLS 1.3: 1-RTT handshake (vs 2-RTT in TLS 1.2)

## Performance Benchmarks

### Connection Pool Impact

| Configuration | RPS | Latency p99 |
|---------------|-----|-------------|
| No pooling | 1,000 | 500ms |
| 10 idle/host | 5,000 | 100ms |
| 100 idle/host | 15,000 | 50ms |
| 1000 total idle | 20,000 | 40ms |

### HTTP/2 vs HTTP/1.1

| Metric | HTTP/1.1 | HTTP/2 |
|--------|----------|---------|
| Connections (1000 req) | 100 | 1 |
| Handshakes | 100 | 1 |
| Bandwidth (headers) | 10MB | 2MB (HPACK) |
| Latency (high concurrency) | 200ms | 50ms |

### QUIC vs TCP+TLS

| Metric | TCP+TLS 1.3 | QUIC |
|--------|-------------|------|
| Connection setup | 1-RTT | 0-RTT (resumed) |
| Handshake latency | 50ms | 0ms (resumed) |
| Packet loss impact | High (HOL blocking) | Low (per-stream) |
| Mobile reconnect | Slow (new handshake) | Fast (migration) |

## Monitoring

### Key Metrics to Track

```bash
# Connection metrics
netstat -an | grep ESTABLISHED | wc -l   # Active connections
netstat -an | grep TIME_WAIT | wc -l     # TIME_WAIT sockets

# Socket buffers
ss -tm                                   # TCP memory usage
ss -um                                   # UDP memory usage

# Connection states
ss -s                                    # Socket statistics

# Dropped packets
netstat -s | grep -i drop                # Dropped packet counters
```

### Prometheus Metrics

Export these from proxy:
- `http_connections_total{protocol="http1|http2|http3"}`
- `http_connection_pool_size{host=""}`
- `http_request_duration_seconds{protocol=""}`
- `tls_handshake_duration_seconds`
- `quic_handshake_duration_seconds`
- `tcp_retransmits_total`

## Troubleshooting

### High Connection Count

**Symptom**: Thousands of TIME_WAIT sockets

**Solution**:
```bash
# Enable TIME_WAIT reuse
sysctl -w net.ipv4.tcp_tw_reuse=1

# Reduce FIN timeout
sysctl -w net.ipv4.tcp_fin_timeout=30
```

### UDP Buffer Overruns (QUIC)

**Symptom**: Packet loss, slow QUIC performance

**Solution**:
```bash
# Increase UDP buffers
sysctl -w net.core.rmem_max=26214400
sysctl -w net.core.wmem_max=26214400

# Check drops
netstat -su | grep "packet receive errors"
```

### TLS Handshake Timeouts

**Symptom**: Connection timeouts during TLS handshake

**Solution**:
```yaml
tuning:
  http:
    tls_handshake_timeout: 30s  # Increase from 10s
```

### Connection Pool Exhaustion

**Symptom**: `connection refused` or high latency

**Solution**:
```yaml
tuning:
  http:
    max_idle_conns: 2000
    max_idle_conns_per_host: 200
```

## Best Practices

### 1. Start Conservative

```yaml
# Conservative production settings
tuning:
  http:
    max_idle_conns: 500
    max_idle_conns_per_host: 50
    idle_conn_timeout: 90s
    http2:
      max_concurrent_streams: 100
```

### 2. Monitor and Iterate

- Track connection pool utilization
- Monitor latency percentiles
- Watch for socket exhaustion
- Profile CPU/memory usage

### 3. Match Backend Capabilities

- Don't enable HTTP/2 if backends don't support it
- Match idle timeouts with backend keep-alive
- Tune buffers based on backend MTU

### 4. Environment-Specific

**Data Center (low latency, high bandwidth)**:
```yaml
tuning:
  http:
    max_idle_conns: 2000
    http2:
      initial_window_size: 2097152  # 2MB
```

**Internet (high latency, packet loss)**:
```yaml
tuning:
  quic:
    enabled: true  # Better for lossy networks
    max_idle_timeout: 60s
  tcp:
    congestion_control: "bbr"  # Better than cubic
```

## Implementation

To implement this configuration, we need to:

1. Add `TuningConfig` struct to `internal/config/config.go`
2. Apply tuning in `internal/proxy/upstream.go` Transport creation
3. Apply tuning in `internal/proxy/server.go` for HTTP/2 and QUIC
4. Add metrics for monitoring tuning effectiveness

See [PROTOCOL_TUNING_IMPLEMENTATION.md](PROTOCOL_TUNING_IMPLEMENTATION.md) for code changes.

## References

- [Go net/http Transport](https://pkg.go.dev/net/http#Transport)
- [Go HTTP/2](https://pkg.go.dev/golang.org/x/net/http2)
- [QUIC-Go Documentation](https://github.com/quic-go/quic-go)
- [Linux TCP Tuning](https://www.kernel.org/doc/Documentation/networking/ip-sysctl.txt)
- [BBR Congestion Control](https://cloud.google.com/blog/products/networking/tcp-bbr-congestion-control-comes-to-gcp-your-internet-just-got-faster)
