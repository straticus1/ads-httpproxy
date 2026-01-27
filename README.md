# ADS HTTP Proxy

Enterprise-grade HTTP/HTTPS/SOCKS5 proxy server with advanced features for traffic inspection, bandwidth management, and plugin extensibility.

## Features

- **Multi-Protocol Support**: HTTP, HTTPS, SOCKS5, gRPC, HTTP-JSON
- **MITM Capabilities**: SSL/TLS interception with custom CA certificate
- **Traffic Mirroring**: Duplicate traffic to secondary destinations for monitoring
- **Plugin Architecture**: Extensible plugin system for custom traffic processing
- **DLP (Data Loss Prevention)**: Content scanning with configurable patterns
- **ICAP Integration**: External content adaptation and filtering
- **Bandwidth Management**: Rate limiting per connection
- **Scripting Engine**: Tengo-based scripting for dynamic traffic manipulation
- **Management API**: RESTful API with signature-based authentication
- **Admin CLI**: Command-line tool for proxy management
- **Visibility & Stats**: Real-time traffic statistics and monitoring

## Architecture

```
ads-httpproxy/
├── cmd/
│   ├── proxy/          # Main proxy server
│   └── admin/          # Admin CLI tool
├── internal/
│   ├── api/            # Management API server
│   ├── bandwidth/      # Bandwidth limiting
│   ├── config/         # Configuration management
│   ├── dlp/            # Data Loss Prevention scanner
│   ├── icap/           # ICAP client integration
│   ├── mitm/           # Man-in-the-middle CA handling
│   ├── pac/            # Proxy Auto-Config handler
│   ├── plugin/         # Plugin architecture
│   ├── proxy/          # Core proxy server (HTTP/SOCKS)
│   ├── scripting/      # Scripting engine
│   └── visibility/     # Statistics and monitoring
└── pkg/
    ├── logging/        # Structured logging (Zap)
    └── mirror/         # Traffic mirroring
```

## Installation

### Prerequisites

- Go 1.25.2 or later

### Build

```bash
# Clone the repository
git clone https://github.com/yourusername/ads-httpproxy.git
cd ads-httpproxy

# Build proxy server
go build -o bin/proxy ./cmd/proxy

# Build admin tool
go build -o bin/admin ./cmd/admin
```

## Configuration

Configuration can be provided via JSON/YAML (planned) or using default values:

```go
{
  "addr": ":8080",              // HTTP/HTTPS proxy address
  "socks_addr": ":1080",        // SOCKS5 proxy address
  "mirror_addr": "",            // Traffic mirror destination
  "ca_cert": "",                // Custom CA certificate path
  "ca_key": "",                 // Custom CA key path
  "api_addr": ":9090",          // Management API address
  "api_secret": "changeme",     // API authentication secret
  "bandwidth_limit": 0,         // Bytes per second (0=unlimited)
  "icap_url": "",               // ICAP server URL
  "dlp_patterns": [],           // DLP regex patterns
  "script_file": ""             // Tengo script path
}
```

## Usage

### Running the Proxy Server

```bash
# Start with default configuration
./bin/proxy

# The proxy will listen on:
# - :8080 for HTTP/HTTPS traffic
# - :1080 for SOCKS5 traffic
# - :9090 for Management API
```

### Using the Admin CLI

```bash
# Check proxy status
./bin/admin -addr http://localhost:9090 -secret changeme -cmd status

# Get configuration
./bin/admin -addr http://localhost:9090 -secret changeme -cmd config
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

### Traffic Mirroring

Enable traffic mirroring by setting `mirror_addr` in the configuration to duplicate all traffic to a secondary destination for analysis or backup.

### MITM SSL Inspection

Configure custom CA certificate and key for SSL/TLS inspection:
- Generate CA certificate
- Configure `ca_cert` and `ca_key` paths
- Install CA certificate in client trust store

### Plugin Development

Plugins can be developed to extend proxy functionality. See `internal/plugin/` for the plugin interface.

### Scripting

Use Tengo scripts to dynamically modify requests/responses:
- Set `script_file` to your Tengo script path
- Access request/response objects from script
- Implement custom business logic

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

## Dependencies

- [goproxy](https://github.com/elazarl/goproxy) - HTTP proxy library
- [go-socks5](https://github.com/armon/go-socks5) - SOCKS5 server
- [tengo](https://github.com/d5/tengo) - Scripting language
- [zap](https://go.uber.org/zap) - Structured logging
- [golang.org/x/net](https://golang.org/x/net) - Network utilities
- [golang.org/x/time](https://golang.org/x/time) - Rate limiting

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
