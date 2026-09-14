# ADS HTTP Proxy

Enterprise-grade HTTP/HTTPS/SOCKS5 proxy server with advanced security features, threat intelligence, and multi-protocol support for production environments.

## Features

### Core Proxy Capabilities
- **Multi-Protocol Support**: HTTP/1.1, HTTP/2, HTTP/3 (QUIC), SOCKS5
- **QUIC proxying**: HTTP/3 gateway termination, explicit HTTP/3 upstream routing, and opaque fixed-target QUIC/UDP relay
- **Developer toolkit**: Bounded traffic inspection, replay CLI, mock responses, and latency/failure rules
- **MASQUE Protocol**: Experimental handlers; RFC CONNECT-UDP/CONNECT-IP conformance is incomplete
- **MITM Capabilities**: SSL/TLS interception with custom CA certificate
- **Dual Mode**: Forward proxy + API Gateway (reverse proxy with routing)
- **Traffic Mirroring**: Duplicate traffic to secondary destinations for monitoring
- **Protocol Detection**: Safeguard against protocol confusion attacks
- **Feature Toggles**: Runtime control of forward/reverse proxy, BrowserID, and MASQUE features

### Security & Access Control
- **Multi-Auth Support**: Basic, NTLM, Kerberos, OIDC, SAML
- **Threat Intelligence**:
  - IP/CIDR blocklist with auto-reload
  - DNS Science integration with gRPC for real-time domain reputation
  - Automatic threat feed refresh
- **Web Application Firewall (WAF)**: OWASP-style pattern matching (SQLi, XSS, Command Injection, Path Traversal)
- **GeoIP Filtering**: MaxMind DB integration with allow/block lists
- **JA3/JA4 Fingerprinting**: Advanced TLS client fingerprinting with full JA4 support
- **BrowserID**: Cryptographically signed browser identity tracking using JA3/JA4 + IP fingerprints
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
│   ├── browserid/      # Browser identity tracking (JA3/JA4 + IP)
│   ├── cache/          # Redis-backed caching layer
│   ├── config/         # Configuration (JSON/YAML + env vars + feature toggles)
│   ├── dlp/            # Data Loss Prevention scanner
│   ├── dnscache/       # DNS Science gRPC client integration
│   ├── geoip/          # GeoIP lookup (MaxMind)
│   ├── grpc/           # gRPC admin API
│   ├── icap/           # ICAP client (REQMOD/RESPMOD)
│   ├── ja3/            # JA3/JA4 TLS fingerprinting
│   ├── masque/         # MASQUE protocol (CONNECT-UDP, CONNECT-IP, Capsule)
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
# Feature Toggles
features:
  forward_proxy: true            # Enable forward proxy mode
  reverse_proxy: true            # Enable reverse proxy/gateway mode
  browser_id: false              # Enable BrowserID tracking
  masque: false                  # Enable MASQUE protocol (CONNECT-UDP/IP)

# Network
addr: ":8080"                    # HTTP/HTTPS proxy
socks_addr: ":1080"              # SOCKS5 proxy
api_addr: ":9090"                # Management API
grpc_addr: ":9091"               # gRPC API

# Performance
enable_reuseport: true           # SO_REUSEPORT for multi-process
enable_quic: false               # Enable HTTP/3 after setting quic_cert and quic_key
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
# Feature toggles
export ADS_FEATURE_FORWARD="true"      # Enable forward proxy
export ADS_FEATURE_REVERSE="true"      # Enable reverse proxy
export ADS_FEATURE_BROWSERID="true"    # Enable BrowserID tracking
export ADS_FEATURE_MASQUE="true"       # Enable MASQUE protocol

# Network
export ADS_ADDR=":8080"
export ADS_ENABLE_QUIC="true"
export ADS_QUIC_CERT="/etc/ads/gateway.crt"
export ADS_QUIC_KEY="/etc/ads/gateway.key"

# Security
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
export ADS_QUIC_CERT="/etc/ads/gateway.crt"
export ADS_QUIC_KEY="/etc/ads/gateway.key"
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

### Deploying to Linux Server

Use the included deployment script for automated setup on remote Linux servers:

```bash
# Build Linux binary first
GOOS=linux GOARCH=amd64 go build -o ads-httpproxy-linux ./cmd/proxy

# Deploy to server (creates systemd service)
./deploy-proxy.sh

# The script will:
# - Upload binary to /opt/ads-httpproxy/bin/
# - Create directory structure
# - Generate default config if missing
# - Install systemd service
# - Set up logging to /opt/ads-httpproxy/logs/

# Start the service
ssh apps2 'systemctl start ads-httpproxy'

# Check status
ssh apps2 'systemctl status ads-httpproxy'

# View logs
ssh apps2 'journalctl -u ads-httpproxy -f'
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

### Developer Toolkit

```bash
./bin/ads-httpproxy -config examples/developer.yaml
export ADS_API_SECRET="local-development-key"
./bin/ads-dev request -url http://example.com
./bin/ads-dev captures
```

See [the developer toolkit guide](docs/developer-toolkit.md) for replay, mocks,
fault rules, HTTP/3 upstreams, and opaque QUIC relaying.

### Using the Admin CLI

```bash
export ADS_API_SECRET="your-api-key"
./bin/ads-admin status -api http://localhost:9090
./bin/ads-admin config
./bin/ads-admin stats -format table
./bin/ads-admin connections -format yaml
./bin/ads-admin metrics
./bin/ads-admin interactive
```

See [the admin CLI guide](docs/admin-cli.md) for configuration defaults, batch
operations, plugin management, and shell completion. Live configuration reload
is disabled; validate a configuration file and restart the service to apply it.

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

### MASQUE Protocol Support

MASQUE CONNECT-UDP and CONNECT-IP handlers are experimental and incomplete.
Use the working HTTP/3 gateway or fixed-target UDP relay for QUIC proxying; see
[developer toolkit and QUIC configuration](docs/developer-toolkit.md).

### BrowserID Tracking

Enable cryptographically signed browser identity tracking based on JA3/JA4 fingerprints and client IP:

```yaml
features:
  browser_id: true
```

BrowserID sets a signed `__ads_bid` cookie that combines:
- TLS fingerprint (JA4 or JA3)
- Client IP address
- HMAC-SHA256 signature for tamper detection

Use cases:
- Bot detection
- Session tracking across IP changes
- Advanced rate limiting
- Fraud prevention

### API Gateway Mode (Reverse Proxy)

Configure reverse proxy routes for API gateway functionality:

```yaml
features:
  reverse_proxy: true

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

See [the plugin development guide](docs/plugins.md) for the public SDK, per-plugin
configuration, version checks, and hot replacement.

Plugins can be developed to extend proxy functionality:

### Dual Scripting Engine

See [the scripting cookbook](docs/scripting-cookbook.md) for tested Tengo and
Starlark request/response policies, header modification, and hot reload.

## API Authentication

The running management API accepts an API key in `X-API-Key`, or Basic
authentication for a configured `api_users` entry. The admin CLI supports both.
Protected routes allow unauthenticated requests when neither API secrets nor
users are configured. `/healthz`, `/metrics`, and `/proxy.pac` are public.

## Security Considerations

- Change the default `api_secret` in production
- Secure CA private keys with appropriate file permissions
- Use HTTPS for the management API in production
- Implement network-level access controls
- Review and audit DLP patterns regularly
- Monitor traffic statistics for anomalies

## Performance Features

- **SO_REUSEPORT**: Multi-process load distribution on Linux and macOS
- **HTTP/3 (QUIC)**: UDP-based multiplexed connections
- **QUIC Relay**: Fixed-target opaque UDP/QUIC forwarding
- **Connection Pooling**: Efficient connection reuse tracking
- **Redis Caching**: High-performance response caching
- **Protocol Detection**: Early detection prevents unnecessary processing
- **JA3/JA4 Fingerprinting**: Fast TLS client identification with SHA256 hashing

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

## Developer and operations guides

- [Developer toolkit and QUIC](docs/developer-toolkit.md)
- [Management API OpenAPI reference](docs/openapi.json)
- [Admin CLI](docs/admin-cli.md)
- [Plugins](docs/plugins.md)
- [Scripting cookbook](docs/scripting-cookbook.md)
- [MITM CA setup](docs/mitm.md)
- [Troubleshooting](docs/troubleshooting.md)
