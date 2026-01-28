# ADS HTTP Proxy

Enterprise-grade HTTP/HTTPS/SOCKS5 proxy server with advanced security features, threat intelligence, and multi-protocol support for production environments.

## Features

### Core Proxy Capabilities
- **Multi-Protocol Support**: HTTP/1.1, HTTP/2, HTTP/3 (QUIC), SOCKS5
- **MITM Capabilities**: SSL/TLS interception with custom CA certificate
- **Dual Mode**: Forward proxy + API Gateway (reverse proxy with routing)
- **Traffic Mirroring**: Duplicate traffic to secondary destinations for monitoring
- **Protocol Detection**: Safeguard against protocol confusion attacks

### Security & Access Control
- **Multi-Auth Support**: Basic, NTLM, Kerberos, OIDC, SAML
- **Threat Intelligence**:
  - IP/CIDR blocklist with auto-reload
  - DNS Science integration with gRPC for real-time domain reputation
  - Automatic threat feed refresh
- **Web Application Firewall (WAF)**: OWASP-style pattern matching (SQLi, XSS, Command Injection, Path Traversal)
- **GeoIP Filtering**: MaxMind DB integration with allow/block lists
- **JA3 Fingerprinting**: TLS client fingerprinting for bot detection
- **DLP (Data Loss Prevention)**: Regex-based content scanning

### Advanced Features
- **ICAP Integration**: External content adaptation and filtering (REQMOD support)
- **Bandwidth Management**: Per-connection rate limiting
- **Dual Scripting Engine**: Tengo + Starlark with hot-reload
- **Redis Caching**: Built-in cache manager for high-performance caching
- **Plugin Architecture**: Extensible plugin system for custom processing

### Operations & Observability
- **Management API**: RESTful API with Prometheus metrics, stats, connection listing
- **Admin CLI Tools**:
  - `ads-admin`: Remote proxy management
  - `squid2ads`: Squid config migration tool
- **Visibility**: Real-time traffic statistics, active connections, uptime tracking
- **PAC File Serving**: Automatic proxy auto-config generation
- **Health Checks**: Kubernetes-ready liveness/readiness probes
- **Deployment Options**: Docker, Kubernetes, systemd, docker-compose

## Architecture

```
ads-httpproxy/
├── cmd/
│   ├── proxy/          # Main proxy server
│   ├── ads-admin/      # Admin CLI tool
│   └── squid2ads/      # Squid config migration utility
├── internal/
│   ├── api/            # Management API server (REST + Prometheus)
│   ├── auth/           # Authentication (NTLM, Kerberos, OIDC, SAML)
│   ├── bandwidth/      # Bandwidth limiting & rate control
│   ├── cache/          # Redis-backed caching layer
│   ├── config/         # Configuration (JSON/YAML + env vars)
│   ├── dlp/            # Data Loss Prevention scanner
│   ├── dnscache/       # DNS Science gRPC client integration
│   ├── geoip/          # GeoIP lookup (MaxMind)
│   ├── grpc/           # gRPC admin API
│   ├── icap/           # ICAP client (REQMOD/RESPMOD)
│   ├── ja3/            # JA3 TLS fingerprinting
│   ├── mitm/           # MITM CA management
│   ├── pac/            # PAC file generator
│   ├── plugin/         # Plugin system
│   ├── protocol/       # Protocol detection safeguard
│   ├── proxy/          # Core proxy (HTTP/SOCKS/TCP gateway)
│   ├── scripting/      # Dual scripting engines:
│   │   ├── tengo/      # Tengo language support
│   │   └── starlark/   # Starlark language support
│   ├── threat/         # Threat intelligence manager
│   ├── visibility/     # Stats, metrics, connection tracking
│   └── waf/            # Web Application Firewall
└── pkg/
    ├── logging/        # Structured logging (Zap)
    └── mirror/         # Traffic mirroring
```

## Installation

### Prerequisites

- Go 1.25.2 or later
- (Optional) Redis for caching
- (Optional) MaxMind GeoIP database for geo-filtering
- (Optional) DNS Science gRPC endpoint for threat intelligence

### Build

```bash
# Clone the repository
git clone https://github.com/yourusername/ads-httpproxy.git
cd ads-httpproxy

# Build all binaries using Makefile
make build

# Or build individually:
go build -o bin/ads-httpproxy ./cmd/proxy
go build -o bin/ads-admin ./cmd/ads-admin
go build -o bin/squid2ads ./cmd/squid2ads

# Run tests
make test

# Build Docker image
make docker
```

## Configuration

Configuration can be provided via:
1. **JSON/YAML file** using `-config` flag
2. **Environment variables** (ADS_* prefix)
3. **Default values** (see `internal/config/config.go`)

### Configuration File Example

See `examples/config.yaml` for a complete reference. Key options:

```yaml
# Network
addr: ":8080"                    # HTTP/HTTPS proxy
socks_addr: ":1080"              # SOCKS5 proxy
api_addr: ":9090"                # Management API
grpc_addr: ":9091"               # gRPC API

# Performance
enable_reuseport: true           # SO_REUSEPORT for multi-process
enable_quic: true                # Enable HTTP/3
bandwidth_limit: 10485760        # Bytes/sec per connection

# Security
auth:
  mechanism: kerberos            # none, basic, ntlm, kerberos, oidc, saml
  krb5_keytab: /etc/krb5.keytab
threat_file: ./threats.txt       # IP/CIDR blocklist
geoip_db_file: ./GeoLite2.mmdb
geoip_block: ["CN", "RU"]        # Block by country

# Content Inspection
dlp_patterns:
  - 'password\s*=\s*\w+'
  - '\d{16}'                     # Credit card pattern
icap_url: icap://scanner:1344/reqmod
script_file: ./policy.star       # or .tengo

# Threat Intelligence
dns_science:
  enabled: true
  api_key: "your-key"
  feed_url: "https://feed.dnsscience.com"
  refresh_interval: "1h"
  rpc_addr: "localhost:50051"    # gRPC endpoint

# Caching
redis:
  enabled: true
  addr: "localhost:6379"
  password: ""
  db: 0

# Protocol Proxies (TCP passthrough)
rtmp_addr: ":1935"
rtmp_target: "upstream:1935"
```

### Environment Variables

All config values can be overridden:
```bash
export ADS_ADDR=":8080"
export ADS_ENABLE_QUIC="true"
export ADS_THREAT_FILE="/etc/threats.txt"
export ADS_DNSSCIENCE_ENABLED="true"
export ADS_REDIS_ENABLED="true"
```

## Usage

### Running the Proxy Server

```bash
# Start with configuration file
./bin/ads-httpproxy -config config.yaml

# Or with environment variables
export ADS_ADDR=":8080"
export ADS_ENABLE_QUIC="true"
./bin/ads-httpproxy

# The proxy will listen on:
# - :8080 for HTTP/HTTPS traffic
# - :1080 for SOCKS5 traffic
# - :9090 for Management API
# - :9091 for gRPC API (if configured)
# - Additional protocol ports (RTMP, RTSP, FTP, SSH) if configured
```

### Using Docker

```bash
# Build
docker build -t ads-httpproxy:latest .

# Run with config
docker run -d \
  -p 8080:8080 \
  -p 1080:1080 \
  -p 9090:9090 \
  -v $(pwd)/config.yaml:/app/config.yaml \
  ads-httpproxy:latest -config /app/config.yaml

# Or use docker-compose
docker-compose up -d
```

### Deploying to Kubernetes

```bash
# Apply manifests
kubectl apply -f deploy/kubernetes/manifests.yaml

# Check status
kubectl get pods -l app=ads-httpproxy
kubectl get svc ads-httpproxy-svc

# Scale up
kubectl scale deployment ads-httpproxy --replicas=5
```

### Using the Admin CLI

```bash
# Check proxy status
./bin/ads-admin -addr http://localhost:9090 -secret changeme -cmd status

# Get configuration
./bin/ads-admin -addr http://localhost:9090 -secret changeme -cmd config

# View statistics
curl http://localhost:9090/stats

# View active connections
curl http://localhost:9090/connections

# Get Prometheus metrics
curl http://localhost:9090/metrics

# Download PAC file
curl http://localhost:9090/proxy.pac
```

### Configure Client Applications

**HTTP/HTTPS Proxy:**
```bash
export http_proxy=http://localhost:8080
export https_proxy=http://localhost:8080
```

**SOCKS5 Proxy:**
```bash
export ALL_PROXY=socks5://localhost:1080
```

## Advanced Features

### API Gateway Mode (Reverse Proxy)

Configure reverse proxy routes for API gateway functionality:

```yaml
routes:
  - path: /api/v1
    upstream: http://backend:8080
    rate_limit: 100  # req/sec
    auth_method: oidc
  - path: /api/v2
    upstream: http://backend2:8080
    auth_method: basic
```

The proxy intelligently switches between forward proxy and reverse proxy modes based on request patterns.

### Traffic Mirroring

Enable traffic mirroring by setting `mirror_addr` to duplicate all traffic to a secondary destination for analysis or backup:

```yaml
mirror_addr: "localhost:8081"  # All traffic duplicated here
```

### MITM SSL Inspection

Configure custom CA certificate and key for SSL/TLS interception:

```bash
# Generate CA
openssl req -x509 -newkey rsa:4096 -keyout ca.key -out ca.crt -days 3650 -nodes

# Configure
ca_cert: ./ca.crt
ca_key: ./ca.key

# Install CA certificate in client trust stores
# macOS: Keychain Access
# Linux: /usr/local/share/ca-certificates/
# Windows: certmgr.msc
```

### Threat Intelligence Integration

**File-Based Blocklist:**
```bash
# threats.txt format (IP/CIDR, one per line)
192.168.1.100
10.0.0.0/8
malicious-domain.com
```

**DNS Science Integration:**
```yaml
dns_science:
  enabled: true
  api_key: "your-api-key"
  feed_url: "https://feed.dnsscience.com/v1/threats"
  refresh_interval: "1h"
  rpc_addr: "dnsscience:50051"  # For real-time gRPC lookups
```

### Plugin Development

Plugins can be developed to extend proxy functionality:

```go
// See internal/plugin/ for the plugin interface
type Plugin interface {
    Name() string
    OnRequest(req *http.Request) error
    OnResponse(resp *http.Response) error
}
```

### Dual Scripting Engine

**Tengo Example** (`policy.tengo`):
```go
fmt := import("fmt")
text := import("text")

// Block requests to specific domains
export func on_request(req) {
    if text.contains(req.host, "blocked.com") {
        return {action: "block", reason: "Forbidden domain"}
    }
    return {action: "allow"}
}
```

**Starlark Example** (`policy.star`):
```python
def on_request(req):
    # Add custom headers
    req.headers["X-Proxy-By"] = "ADS-HTTP-Proxy"

    # Log request
    print("Request to:", req.url)

    return {"action": "allow"}

def on_response(resp):
    # Modify response
    if resp.status_code >= 400:
        print("Error response:", resp.status_code)
    return {"action": "allow"}
```

**Hot-Reload:**
Script files are watched for changes and automatically reloaded without restarting the proxy.

## API Authentication

The management API uses signature-based authentication:
1. Calculate signature: `HMAC-SHA256(secret, METHOD + PATH + TIMESTAMP)`
2. Include headers:
   - `X-Timestamp`: RFC3339 timestamp
   - `X-Signature`: Hex-encoded HMAC signature

## Security Considerations

- Change the default `api_secret` in production
- Secure CA private keys with appropriate file permissions
- Use HTTPS for the management API in production
- Implement network-level access controls
- Review and audit DLP patterns regularly
- Monitor traffic statistics for anomalies

## Performance Features

- **SO_REUSEPORT**: Multi-process load distribution on Linux
- **HTTP/3 (QUIC)**: UDP-based multiplexed connections
- **Connection Pooling**: Efficient connection reuse tracking
- **Redis Caching**: High-performance response caching
- **Protocol Detection**: Early detection prevents unnecessary processing
- **JA3 Fingerprinting**: Fast TLS client identification

## Monitoring & Observability

**Prometheus Metrics:**
- Request/response counters
- Bandwidth usage
- Active connections
- Error rates
- Latency histograms

**Stats Endpoint (`/stats`):**
```json
{
  "active_connections": 42,
  "total_requests": 15234,
  "total_bytes_sent": 52428800,
  "total_bytes_received": 10485760,
  "uptime": "2h15m30s"
}
```

**Connections Endpoint (`/connections`):**
```json
[
  {
    "id": "192.168.1.100:54321",
    "remote": "192.168.1.100:54321",
    "start_time": "2026-01-28T12:30:00Z"
  }
]
```

## Dependencies

### Core
- [goproxy](https://github.com/elazarl/goproxy) - HTTP proxy library
- [go-socks5](https://github.com/armon/go-socks5) - SOCKS5 server
- [quic-go](https://github.com/quic-go/quic-go) - HTTP/3 support
- [zap](https://go.uber.org/zap) - Structured logging

### Scripting
- [tengo](https://github.com/d5/tengo) - Tengo scripting language
- [starlark](https://go.starlark.net) - Starlark (Python-like) scripting

### Security
- [gokrb5](https://github.com/jcmturner/gokrb5) - Kerberos authentication
- [go-oidc](https://github.com/coreos/go-oidc) - OIDC authentication
- [saml](https://github.com/crewjam/saml) - SAML authentication
- [maxminddb](https://github.com/oschwald/maxminddb-golang) - GeoIP lookups

### Infrastructure
- [redis](https://github.com/go-redis/redis) - Caching layer
- [prometheus](https://github.com/prometheus/client_golang) - Metrics
- [grpc](https://google.golang.org/grpc) - gRPC APIs
- [fsnotify](https://github.com/fsnotify/fsnotify) - File watching (hot-reload)

## License

[License Type] - See LICENSE file for details

## Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## Support

For issues, questions, or contributions, please open an issue on GitHub.
