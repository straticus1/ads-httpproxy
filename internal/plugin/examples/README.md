# Example Plugins

This directory contains example plugins demonstrating various use cases.

## Available Examples

### 1. Header Injector (`header_injector.go`)
Injects custom headers into requests and responses.

**Use Cases**:
- Add company branding headers
- Inject security headers (CSP, HSTS, X-Frame-Options)
- Add tracking headers for analytics

**Example**:
```go
plugin := NewHeaderInjectorPlugin(
    map[string]string{
        "X-Forwarded-By": "ADS-HTTPProxy",
        "X-Company": "Acme Corp",
    },
    map[string]string{
        "X-Content-Security-Policy": "default-src 'self'",
        "X-Frame-Options": "DENY",
    },
)
```

### 2. Logger (`logger.go`)
Logs all requests and responses with detailed information.

**Use Cases**:
- Audit trail
- Compliance logging
- Debugging
- Analytics

**Features**:
- Configurable header logging
- Structured logging with zap
- Timestamp tracking

### 3. URL Filter (`url_filter.go`)
Blocks requests to specific domains or URL patterns.

**Use Cases**:
- Block malicious domains
- Enforce acceptable use policy
- Category-based filtering
- Pattern matching (regex)

**Example**:
```go
plugin := NewURLFilterPlugin(
    []string{"malware.com", "phishing.net"},  // Blocked domains
    []string{`.*\.exe$`, `.*download.*virus.*`},  // Blocked patterns
    []string{"trusted.com"},  // Allowed domains (whitelist)
)
```

### 4. Rate Limiter (`rate_limiter.go`)
Implements per-IP rate limiting.

**Use Cases**:
- DDoS protection
- API rate limiting
- Fair usage enforcement
- Prevent abuse

**Features**:
- Configurable window and max requests
- Per-IP tracking
- Automatic cleanup of expired entries

**Example**:
```go
plugin := NewRateLimiterPlugin(
    100,              // Max 100 requests
    1 * time.Minute,  // Per minute
)
```

### 5. Content Type Blocker (`content_type_blocker.go`)
Blocks responses with specific content types.

**Use Cases**:
- Block executable downloads
- Prevent PDF downloads
- Filter multimedia content
- Enforce data types

**Example**:
```go
plugin := NewContentTypeBlockerPlugin([]string{
    "application/x-executable",
    "application/x-msdownload",
    "application/pdf",
})
```

## Using These Examples

### Option 1: As Go Plugin (.so)

1. Build as shared library:
```bash
go build -buildmode=plugin -o header_injector.so header_injector.go
```

2. Deploy to plugin directory:
```bash
sudo cp header_injector.so /etc/ads-httpproxy/plugins/
```

3. Configure in `config.yaml`:
```yaml
plugins:
  enabled: true
  plugin_dir: "/etc/ads-httpproxy/plugins"
  auto_load: true
```

### Option 2: Embedded in Proxy

Import directly in server code:

```go
import "ads-httpproxy/internal/plugin/examples"

// Register plugins
pm := plugin.NewManager()

// Header injector
pm.Register(examples.NewHeaderInjectorPlugin(
    map[string]string{"X-Company": "Acme"},
    map[string]string{"X-Frame-Options": "DENY"},
))

// Logger
pm.Register(examples.NewLoggerPlugin(true, false))

// URL Filter
urlFilter, _ := examples.NewURLFilterPlugin(
    []string{"blocked.com"},
    []string{},
    []string{},
)
pm.Register(urlFilter)

// Rate Limiter
pm.Register(examples.NewRateLimiterPlugin(100, 1*time.Minute))

// Content Type Blocker
pm.Register(examples.NewContentTypeBlockerPlugin([]string{"application/x-executable"}))
```

## Testing

Test plugins locally before deployment:

```bash
go test ./internal/plugin/examples/...
```

## Performance

All example plugins are designed with performance in mind:

| Plugin | Latency Overhead | Memory Usage |
|--------|------------------|--------------|
| Header Injector | < 1ms | Negligible |
| Logger | < 2ms | ~100 bytes/request |
| URL Filter | < 3ms | ~1KB (pattern cache) |
| Rate Limiter | < 2ms | ~100 bytes/IP |
| Content Type Blocker | < 1ms | Negligible |

## Customization

These examples are meant to be customized for your needs:

1. **Copy example** to your own plugin project
2. **Modify** logic to fit your requirements
3. **Add configuration** from external files
4. **Test** thoroughly
5. **Deploy** to production

## Security Considerations

- **URL Filter**: Patterns are evaluated on every request - keep regex simple
- **Rate Limiter**: Uses in-memory storage - not suitable for distributed deployments
- **Logger**: Sensitive data in headers - configure carefully
- **Content Type Blocker**: Based on Content-Type header - can be spoofed

## Further Reading

- [PLUGIN_DEVELOPMENT.md](../../../PLUGIN_DEVELOPMENT.md) - Complete plugin development guide
- [plugin.go](../plugin.go) - Plugin interface documentation
- [manager.go](../manager.go) - Plugin manager implementation

## Contributing

Contribute your own example plugins:

1. Create plugin in this directory
2. Add documentation
3. Submit pull request

## License

Same as ads-httpproxy project.
