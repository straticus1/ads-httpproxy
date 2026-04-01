package examples

import (
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
}

type clientRateLimit struct {
	requests  int
	resetTime time.Time
}

func NewRateLimiterPlugin(maxRequests int, window time.Duration) *RateLimiterPlugin {
	plugin := &RateLimiterPlugin{
		MaxRequests: maxRequests,
		Window:      window,
		clients:     make(map[string]*clientRateLimit),
	}

	// Start cleanup goroutine
	go plugin.cleanup()

	return plugin
}

func (p *RateLimiterPlugin) Name() string {
	return "rate-limiter"
}

func (p *RateLimiterPlugin) OnRequest(req *http.Request, ctx *plugin.Context) (*http.Request, *http.Response) {
	clientIP := req.RemoteAddr

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
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
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
