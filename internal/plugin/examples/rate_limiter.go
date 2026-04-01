package examples

import (
	"net"
	"net/http"
	"sync"
	"time"

	"ads-httpproxy/internal/plugin"
	"ads-httpproxy/pkg/logging"

	"github.com/elazarl/goproxy"
	"go.uber.org/zap"
)

// RateLimiterPlugin implements per-IP rate limiting
type RateLimiterPlugin struct {
	MaxRequests int           // Max requests per window
	Window      time.Duration // Time window
	mu          sync.RWMutex
	clients     map[string]*clientRateLimit
	shutdown    chan struct{}
	wg          sync.WaitGroup
}

type clientRateLimit struct {
	requests  int
	resetTime time.Time
}

func NewRateLimiterPlugin(maxRequests int, window time.Duration) *RateLimiterPlugin {
	if maxRequests <= 0 {
		maxRequests = 100
	}
	if window <= 0 {
		window = 1 * time.Minute
	}

	plugin := &RateLimiterPlugin{
		MaxRequests: maxRequests,
		Window:      window,
		clients:     make(map[string]*clientRateLimit),
		shutdown:    make(chan struct{}),
	}

	// Start cleanup goroutine
	plugin.wg.Add(1)
	go plugin.cleanup()

	return plugin
}

// Shutdown gracefully stops the rate limiter
func (p *RateLimiterPlugin) Shutdown() {
	close(p.shutdown)
	p.wg.Wait()
}

func (p *RateLimiterPlugin) Name() string {
	return "rate-limiter"
}

func (p *RateLimiterPlugin) OnRequest(req *http.Request, ctx *plugin.Context) (*http.Request, *http.Response) {
	if req == nil {
		return req, nil
	}

	// Extract IP address without port
	clientIP, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		// If no port, use RemoteAddr as-is
		clientIP = req.RemoteAddr
	}

	// Check X-Forwarded-For header for real client IP
	if xff := req.Header.Get("X-Forwarded-For"); xff != "" {
		// Use first IP in X-Forwarded-For chain
		if idx := len(xff); idx > 0 {
			if commaIdx := 0; commaIdx < idx {
				for i, c := range xff {
					if c == ',' {
						clientIP = xff[:i]
						break
					}
				}
				if commaIdx == 0 {
					clientIP = xff
				}
			}
		}
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	now := time.Now()

	// Get or create client rate limit
	client, exists := p.clients[clientIP]
	if !exists || now.After(client.resetTime) {
		// New client or window expired
		p.clients[clientIP] = &clientRateLimit{
			requests:  1,
			resetTime: now.Add(p.Window),
		}
		return req, nil
	}

	// Check if rate limit exceeded
	if client.requests >= p.MaxRequests {
		logging.Logger.Warn("Plugin: Rate limit exceeded",
			zap.String("plugin", p.Name()),
			zap.String("client_ip", clientIP),
			zap.Int("requests", client.requests),
			zap.Int("max_requests", p.MaxRequests))

		return req, goproxy.NewResponse(req, goproxy.ContentTypeText, http.StatusTooManyRequests, "Rate Limit Exceeded")
	}

	// Increment counter
	client.requests++
	return req, nil
}

func (p *RateLimiterPlugin) OnResponse(resp *http.Response, ctx *plugin.Context) *http.Response {
	// No response modification
	return resp
}

// cleanup removes expired client entries
func (p *RateLimiterPlugin) cleanup() {
	defer p.wg.Done()

	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-p.shutdown:
			return
		case <-ticker.C:
			p.mu.Lock()
			now := time.Now()
			for ip, client := range p.clients {
				if now.After(client.resetTime) {
					delete(p.clients, ip)
				}
			}
			p.mu.Unlock()
		}
	}
}
