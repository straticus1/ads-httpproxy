# Plugin Development Guide

Complete guide to developing plugins for ads-httpproxy.

## Overview

The plugin system allows you to extend the proxy's functionality without modifying core code. Plugins can:

- **Inspect** requests and responses
- **Modify** headers, URLs, and content
- **Block** requests based on custom logic
- **Log** traffic for auditing
- **Enforce** custom policies

## Plugin Architecture

```
Request Flow:
Browser → Proxy → Built-in Middleware → Plugins → Upstream Server
                                           ↓
                                      OnRequest()

Response Flow:
Browser ← Proxy ← Built-in Middleware ← Plugins ← Upstream Server
                                           ↓
                                      OnResponse()
```

**Execution Order**:
1. Threat Intel (IP/Domain blocking)
2. GeoIP (Country blocking)
3. Authentication (LDAP, OAuth2, etc.)
4. Policy Engine (CEL policies)
5. Reputation (URL feeds)
6. WAF (Web Application Firewall)
7. DLP (Data Loss Prevention)
8. **Plugins** ← Your custom logic here
9. Upstream

## Plugin Interface

```go
package plugin

import "net/http"

// Plugin defines the interface all plugins must implement
type Plugin interface {
    // Name returns unique plugin identifier
    Name() string

    // OnRequest is called before sending request to upstream
    // Returns:
    //   - modified request (or nil to use original)
    //   - response (if not nil, request is blocked and response returned to client)
    OnRequest(req *http.Request, ctx *Context) (*http.Request, *http.Response)

    // OnResponse is called after receiving response from upstream
    // Returns modified response
    OnResponse(resp *http.Response, ctx *Context) *http.Response
}

// Context provides access to proxy state and session data
type Context struct {
    // Add custom fields as needed
}
```

## Creating a Plugin

### Step 1: Write Plugin Code

Create a new Go file (e.g., `my_plugin.go`):

```go
package main

import (
    "net/http"
    "ads-httpproxy/internal/plugin"
)

// MyPlugin implements the Plugin interface
type MyPlugin struct {
    // Add configuration fields
    BlockedUserAgents []string
}

func (p *MyPlugin) Name() string {
    return "my-plugin"
}

func (p *MyPlugin) OnRequest(req *http.Request, ctx *plugin.Context) (*http.Request, *http.Response) {
    // Check if User-Agent is blocked
    userAgent := req.Header.Get("User-Agent")
    for _, blocked := range p.BlockedUserAgents {
        if userAgent == blocked {
            // Block request
            return req, &http.Response{
                StatusCode: http.StatusForbidden,
                Status:     "403 Forbidden",
                Body:       http.NoBody,
                Header:     make(http.Header),
            }
        }
    }

    // Allow request
    return req, nil
}

func (p *MyPlugin) OnResponse(resp *http.Response, ctx *plugin.Context) *http.Response {
    // Add custom response header
    resp.Header.Set("X-My-Plugin", "processed")
    return resp
}

// NewPlugin is the entry point called by the plugin loader
func NewPlugin() plugin.Plugin {
    return &MyPlugin{
        BlockedUserAgents: []string{"BadBot", "Scraper"},
    }
}
```

### Step 2: Build as Shared Library

```bash
go build -buildmode=plugin -o my_plugin.so my_plugin.go
```

**Important**: The plugin must be built with the **exact same Go version** as the proxy binary.

### Step 3: Deploy Plugin

Copy the `.so` file to your plugin directory:

```bash
sudo mkdir -p /etc/ads-httpproxy/plugins
sudo cp my_plugin.so /etc/ads-httpproxy/plugins/
```

### Step 4: Configure Proxy

Add plugin configuration to `config.yaml`:

```yaml
plugins:
  enabled: true
  plugin_dir: "/etc/ads-httpproxy/plugins"
  auto_load: true
```

Or load specific plugin:

```yaml
plugins:
  enabled: true
  plugin_list:
    - "/etc/ads-httpproxy/plugins/my_plugin.so"
```

## Example Plugins

### 1. Header Injector

Inject custom headers into requests/responses:

```go
package main

import (
    "net/http"
    "ads-httpproxy/internal/plugin"
)

type HeaderInjectorPlugin struct {
    RequestHeaders  map[string]string
    ResponseHeaders map[string]string
}

func (p *HeaderInjectorPlugin) Name() string {
    return "header-injector"
}

func (p *HeaderInjectorPlugin) OnRequest(req *http.Request, ctx *plugin.Context) (*http.Request, *http.Response) {
    for key, value := range p.RequestHeaders {
        req.Header.Set(key, value)
    }
    return req, nil
}

func (p *HeaderInjectorPlugin) OnResponse(resp *http.Response, ctx *plugin.Context) *http.Response {
    for key, value := range p.ResponseHeaders {
        resp.Header.Set(key, value)
    }
    return resp
}

func NewPlugin() plugin.Plugin {
    return &HeaderInjectorPlugin{
        RequestHeaders: map[string]string{
            "X-Forwarded-By": "ADS-HTTPProxy",
            "X-Company":      "Acme Corp",
        },
        ResponseHeaders: map[string]string{
            "X-Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options":           "DENY",
        },
    }
}
```

### 2. Request Logger

Log all requests with detailed information:

```go
package main

import (
    "net/http"
    "time"
    "ads-httpproxy/internal/plugin"
    "ads-httpproxy/pkg/logging"
    "go.uber.org/zap"
)

type LoggerPlugin struct {
    LogHeaders bool
}

func (p *LoggerPlugin) Name() string {
    return "logger"
}

func (p *LoggerPlugin) OnRequest(req *http.Request, ctx *plugin.Context) (*http.Request, *http.Response) {
    fields := []zap.Field{
        zap.String("method", req.Method),
        zap.String("url", req.URL.String()),
        zap.String("host", req.Host),
        zap.String("remote_addr", req.RemoteAddr),
        zap.Time("timestamp", time.Now()),
    }

    if p.LogHeaders {
        headers := make(map[string][]string)
        for k, v := range req.Header {
            headers[k] = v
        }
        fields = append(fields, zap.Any("headers", headers))
    }

    logging.Logger.Info("Plugin: Request", fields...)
    return req, nil
}

func (p *LoggerPlugin) OnResponse(resp *http.Response, ctx *plugin.Context) *http.Response {
    logging.Logger.Info("Plugin: Response",
        zap.Int("status_code", resp.StatusCode),
        zap.String("status", resp.Status))
    return resp
}

func NewPlugin() plugin.Plugin {
    return &LoggerPlugin{
        LogHeaders: true,
    }
}
```

### 3. URL Filter

Block requests to specific domains or patterns:

```go
package main

import (
    "net/http"
    "regexp"
    "strings"
    "ads-httpproxy/internal/plugin"
)

type URLFilterPlugin struct {
    BlockedDomains []string
    BlockedPatterns []*regexp.Regexp
}

func (p *URLFilterPlugin) Name() string {
    return "url-filter"
}

func (p *URLFilterPlugin) OnRequest(req *http.Request, ctx *plugin.Context) (*http.Request, *http.Response) {
    host := req.URL.Hostname()
    fullURL := req.URL.String()

    // Check blocked domains
    for _, blocked := range p.BlockedDomains {
        if strings.Contains(host, blocked) {
            return req, &http.Response{
                StatusCode: http.StatusForbidden,
                Status:     "403 Forbidden",
                Body:       http.NoBody,
                Header:     make(http.Header),
            }
        }
    }

    // Check blocked patterns
    for _, pattern := range p.BlockedPatterns {
        if pattern.MatchString(fullURL) {
            return req, &http.Response{
                StatusCode: http.StatusForbidden,
                Status:     "403 Forbidden",
                Body:       http.NoBody,
                Header:     make(http.Header),
            }
        }
    }

    return req, nil
}

func (p *URLFilterPlugin) OnResponse(resp *http.Response, ctx *plugin.Context) *http.Response {
    return resp
}

func NewPlugin() plugin.Plugin {
    return &URLFilterPlugin{
        BlockedDomains: []string{"malware.com", "phishing.net"},
        BlockedPatterns: []*regexp.Regexp{
            regexp.MustCompile(`.*\.exe$`),
            regexp.MustCompile(`.*download.*virus.*`),
        },
    }
}
```

### 4. Rate Limiter

Per-IP rate limiting:

```go
package main

import (
    "net/http"
    "sync"
    "time"
    "ads-httpproxy/internal/plugin"
)

type RateLimiterPlugin struct {
    MaxRequests int
    Window      time.Duration
    mu          sync.RWMutex
    clients     map[string]*clientRateLimit
}

type clientRateLimit struct {
    requests  int
    resetTime time.Time
}

func (p *RateLimiterPlugin) Name() string {
    return "rate-limiter"
}

func (p *RateLimiterPlugin) OnRequest(req *http.Request, ctx *plugin.Context) (*http.Request, *http.Response) {
    clientIP := req.RemoteAddr

    p.mu.Lock()
    defer p.mu.Unlock()

    now := time.Now()
    client, exists := p.clients[clientIP]

    if !exists || now.After(client.resetTime) {
        p.clients[clientIP] = &clientRateLimit{
            requests:  1,
            resetTime: now.Add(p.Window),
        }
        return req, nil
    }

    if client.requests >= p.MaxRequests {
        return req, &http.Response{
            StatusCode: http.StatusTooManyRequests,
            Status:     "429 Too Many Requests",
            Body:       http.NoBody,
            Header:     make(http.Header),
        }
    }

    client.requests++
    return req, nil
}

func (p *RateLimiterPlugin) OnResponse(resp *http.Response, ctx *plugin.Context) *http.Response {
    return resp
}

func NewPlugin() plugin.Plugin {
    return &RateLimiterPlugin{
        MaxRequests: 100,
        Window:      1 * time.Minute,
        clients:     make(map[string]*clientRateLimit),
    }
}
```

### 5. Content Type Blocker

Block responses with specific content types:

```go
package main

import (
    "io"
    "net/http"
    "strings"
    "ads-httpproxy/internal/plugin"
)

type ContentTypeBlockerPlugin struct {
    BlockedTypes []string
}

func (p *ContentTypeBlockerPlugin) Name() string {
    return "content-type-blocker"
}

func (p *ContentTypeBlockerPlugin) OnRequest(req *http.Request, ctx *plugin.Context) (*http.Request, *http.Response) {
    return req, nil
}

func (p *ContentTypeBlockerPlugin) OnResponse(resp *http.Response, ctx *plugin.Context) *http.Response {
    contentType := resp.Header.Get("Content-Type")

    for _, blocked := range p.BlockedTypes {
        if strings.Contains(strings.ToLower(contentType), strings.ToLower(blocked)) {
            // Close original body
            if resp.Body != nil {
                io.Copy(io.Discard, resp.Body)
                resp.Body.Close()
            }

            // Return blocked response
            return &http.Response{
                StatusCode: http.StatusForbidden,
                Status:     "403 Forbidden",
                Body:       http.NoBody,
                Header:     resp.Header,
                Request:    resp.Request,
            }
        }
    }

    return resp
}

func NewPlugin() plugin.Plugin {
    return &ContentTypeBlockerPlugin{
        BlockedTypes: []string{
            "application/x-executable",
            "application/x-msdownload",
            "application/x-msdos-program",
        },
    }
}
```

## Advanced Topics

### Configuration from File

Load plugin configuration from external file:

```go
package main

import (
    "encoding/json"
    "net/http"
    "os"
    "ads-httpproxy/internal/plugin"
)

type MyPluginConfig struct {
    BlockedDomains []string `json:"blocked_domains"`
    AllowedIPs     []string `json:"allowed_ips"`
}

type MyPlugin struct {
    config *MyPluginConfig
}

func (p *MyPlugin) Name() string {
    return "my-plugin"
}

func (p *MyPlugin) OnRequest(req *http.Request, ctx *plugin.Context) (*http.Request, *http.Response) {
    // Use config
    return req, nil
}

func (p *MyPlugin) OnResponse(resp *http.Response, ctx *plugin.Context) *http.Response {
    return resp
}

func NewPlugin() plugin.Plugin {
    // Load config from file
    file, err := os.Open("/etc/ads-httpproxy/my-plugin-config.json")
    if err != nil {
        panic(err)
    }
    defer file.Close()

    var config MyPluginConfig
    if err := json.NewDecoder(file).Decode(&config); err != nil {
        panic(err)
    }

    return &MyPlugin{config: &config}
}
```

### Accessing Proxy Context

Access session data and proxy state:

```go
func (p *MyPlugin) OnRequest(req *http.Request, ctx *plugin.Context) (*http.Request, *http.Response) {
    // Context can contain:
    // - Session ID
    // - Authenticated user
    // - Custom metadata

    // Currently Context is empty, but can be extended:
    // ctx.UserID
    // ctx.SessionID
    // ctx.TenantID

    return req, nil
}
```

### Stateful Plugins

Maintain state across requests:

```go
type StatefulPlugin struct {
    mu      sync.RWMutex
    counter map[string]int
}

func (p *StatefulPlugin) OnRequest(req *http.Request, ctx *plugin.Context) (*http.Request, *http.Response) {
    p.mu.Lock()
    defer p.mu.Unlock()

    key := req.URL.Host
    p.counter[key]++

    return req, nil
}
```

### External API Integration

Call external services:

```go
type APIPlugin struct {
    client *http.Client
    apiURL string
}

func (p *APIPlugin) OnRequest(req *http.Request, ctx *plugin.Context) (*http.Request, *http.Response) {
    // Call external API for validation
    checkReq, _ := http.NewRequest("GET", p.apiURL+"/check?url="+req.URL.String(), nil)
    checkResp, err := p.client.Do(checkReq)
    if err != nil {
        // Fail open
        return req, nil
    }
    defer checkResp.Body.Close()

    if checkResp.StatusCode == http.StatusForbidden {
        return req, &http.Response{
            StatusCode: http.StatusForbidden,
            Status:     "403 Forbidden",
            Body:       http.NoBody,
            Header:     make(http.Header),
        }
    }

    return req, nil
}

func NewPlugin() plugin.Plugin {
    return &APIPlugin{
        client: &http.Client{Timeout: 5 * time.Second},
        apiURL: "https://api.threatintel.com",
    }
}
```

## Best Practices

### 1. Error Handling

Always handle errors gracefully:

```go
func (p *MyPlugin) OnRequest(req *http.Request, ctx *plugin.Context) (*http.Request, *http.Response) {
    result, err := p.someOperation()
    if err != nil {
        // Log error but don't crash
        logging.Logger.Error("Plugin error", zap.Error(err))
        // Fail open (allow request)
        return req, nil
    }
    return req, nil
}
```

### 2. Performance

- **Minimize latency**: Plugins add overhead to every request
- **Use timeouts**: Don't block indefinitely
- **Cache results**: Cache expensive operations
- **Avoid heavy I/O**: Use async operations when possible

```go
type CachingPlugin struct {
    cache sync.Map // Use concurrent map for caching
}

func (p *CachingPlugin) OnRequest(req *http.Request, ctx *plugin.Context) (*http.Request, *http.Response) {
    key := req.URL.Host

    // Check cache
    if cached, ok := p.cache.Load(key); ok {
        return cached.(*http.Request), nil
    }

    // Expensive operation
    result := p.expensiveCheck(req)

    // Store in cache
    p.cache.Store(key, result)

    return result, nil
}
```

### 3. Thread Safety

All plugins must be thread-safe:

```go
type SafePlugin struct {
    mu    sync.RWMutex // Use RWMutex for read-heavy workloads
    data  map[string]int
}

func (p *SafePlugin) OnRequest(req *http.Request, ctx *plugin.Context) (*http.Request, *http.Response) {
    p.mu.Lock()
    defer p.mu.Unlock()

    p.data["count"]++

    return req, nil
}
```

### 4. Logging

Use structured logging:

```go
import "go.uber.org/zap"

func (p *MyPlugin) OnRequest(req *http.Request, ctx *plugin.Context) (*http.Request, *http.Response) {
    logging.Logger.Info("Plugin processing request",
        zap.String("plugin", p.Name()),
        zap.String("method", req.Method),
        zap.String("url", req.URL.String()),
        zap.String("remote_addr", req.RemoteAddr))

    return req, nil
}
```

### 5. Resource Cleanup

Clean up resources properly:

```go
type ResourcePlugin struct {
    conn *sql.DB
    done chan struct{}
}

func (p *ResourcePlugin) Name() string {
    return "resource-plugin"
}

func (p *ResourcePlugin) OnRequest(req *http.Request, ctx *plugin.Context) (*http.Request, *http.Response) {
    return req, nil
}

func (p *ResourcePlugin) OnResponse(resp *http.Response, ctx *plugin.Context) *http.Response {
    return resp
}

func (p *ResourcePlugin) Close() error {
    close(p.done)
    return p.conn.Close()
}

func NewPlugin() plugin.Plugin {
    db, err := sql.Open("postgres", "connection-string")
    if err != nil {
        panic(err)
    }

    plugin := &ResourcePlugin{
        conn: db,
        done: make(chan struct{}),
    }

    // Start cleanup goroutine
    go func() {
        <-plugin.done
        db.Close()
    }()

    return plugin
}
```

## Debugging

### Enable Debug Logging

Set log level to debug:

```bash
export LOG_LEVEL=debug
./ads-httpproxy -config config.yaml
```

### Test Plugin Locally

Before building as `.so`, test plugin logic:

```go
package main

import (
    "net/http"
    "testing"
)

func TestMyPlugin(t *testing.T) {
    plugin := NewPlugin()

    req, _ := http.NewRequest("GET", "http://example.com", nil)
    ctx := &Context{}

    modReq, resp := plugin.OnRequest(req, ctx)

    if resp != nil {
        t.Errorf("Expected nil response, got %v", resp)
    }

    if modReq == nil {
        t.Error("Expected modified request")
    }
}
```

### Common Issues

**Issue**: `plugin was built with a different version of package`

**Solution**: Rebuild plugin with same Go version as proxy:

```bash
go version  # Check Go version
go build -buildmode=plugin -o plugin.so plugin.go
```

**Issue**: `undefined symbol: NewPlugin`

**Solution**: Ensure `NewPlugin()` function is exported (starts with capital N)

**Issue**: Plugin crashes proxy

**Solution**: Check for panics, nil pointers, and race conditions

## Deployment

### Production Checklist

- [ ] Plugin is thread-safe
- [ ] Error handling is graceful (fail open)
- [ ] Performance is acceptable (< 10ms overhead)
- [ ] Logging is structured and informative
- [ ] Resources are cleaned up properly
- [ ] Plugin is tested under load
- [ ] Plugin configuration is documented
- [ ] Plugin binary is built with matching Go version

### Rollout Strategy

1. **Test in development** with synthetic traffic
2. **Deploy to staging** with real traffic sample
3. **Monitor metrics**: latency, error rate, throughput
4. **Gradual rollout**: 1% → 10% → 50% → 100%
5. **Have rollback plan**: Disable plugin via config

### Monitoring

Track plugin performance:

```go
import "time"

func (p *MyPlugin) OnRequest(req *http.Request, ctx *plugin.Context) (*http.Request, *http.Response) {
    start := time.Now()
    defer func() {
        duration := time.Since(start)
        if duration > 10*time.Millisecond {
            logging.Logger.Warn("Plugin slow",
                zap.String("plugin", p.Name()),
                zap.Duration("duration", duration))
        }
    }()

    // Plugin logic
    return req, nil
}
```

## Contributing Plugins

Share your plugins with the community:

1. Create GitHub repository
2. Add documentation and examples
3. Submit to plugin registry (future)

## Support

- **Documentation**: [PLUGIN_DEVELOPMENT.md](PLUGIN_DEVELOPMENT.md)
- **Examples**: `internal/plugin/examples/`
- **Issues**: [GitHub Issues](https://github.com/straticus1/ads-httpproxy/issues)

## Future Enhancements

- [ ] Plugin configuration via API
- [ ] Plugin marketplace/registry
- [ ] Hot-reload plugins without restart
- [ ] Plugin versioning and dependencies
- [ ] WebAssembly plugin support
- [ ] Plugin sandboxing for security
