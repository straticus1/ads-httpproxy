package proxy

import (
	"context"
	"net"
	"net/http"
	"time"

	"strings"

	"ads-httpproxy/internal/api"
	"ads-httpproxy/internal/auth"
	"ads-httpproxy/internal/bandwidth"
	"ads-httpproxy/internal/cache"
	"ads-httpproxy/internal/config"
	"ads-httpproxy/internal/dlp"
	"ads-httpproxy/internal/geoip"
	"ads-httpproxy/internal/icap"
	"ads-httpproxy/internal/mitm"
	"ads-httpproxy/internal/plugin"
	"ads-httpproxy/internal/scripting/engine"
	"ads-httpproxy/internal/scripting/starlark"
	"ads-httpproxy/internal/scripting/tengo"
	"ads-httpproxy/internal/threat"
	"ads-httpproxy/internal/visibility"
	"ads-httpproxy/internal/waf"
	"ads-httpproxy/pkg/logging"
	"net/http/httputil"
	"net/url"

	dnscache "ads-httpproxy/internal/dnscache"

	"github.com/elazarl/goproxy"
	"github.com/quic-go/quic-go/http3"
	"go.uber.org/zap"
)

type RequestMiddleware func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response)

type Server struct {
	cfg           *config.Config
	proxy         *goproxy.ProxyHttpServer
	pm            *plugin.Manager
	apiServer     *api.Server
	limiter       *bandwidth.Limiter
	icapClient    *icap.Client
	dlpScanner    *dlp.RegexScanner
	wafScanner    *waf.Scanner
	threatMgr     *threat.Manager
	geoIP         *geoip.Lookup
	scriptEngine  engine.Engine
	authenticator auth.Authenticator
	cache         *cache.Manager
	httpServer    *http.Server
	middleware    []RequestMiddleware
}

func NewServer(cfg *config.Config) *Server {
	p := goproxy.NewProxyHttpServer()
	p.Verbose = true // Enable verbose logging for now
	// Important for gRPC/Streaming: flush immediately
	// 0 usually means "default" in some libs, but for goproxy we need to ensure it flushes.
	// Actually goproxy uses http.Transport which handles it, but let's check if there's a flush setting exposed.
	// goproxy doesn't expose FlushInterval directly on the struct easily,
	// but usage of Copy/IoCopy usually respects it.
	// However, we can ensure the Transport is http2 enabled.
	// By default, Go's http.Transport enables http2.

	// Configure MITM
	ca, err := mitm.LoadCA(cfg.CaCert, cfg.CaKey)
	if err != nil {
		logging.Logger.Error("Failed to load CA, falling back to default", zap.Error(err))
		ca = &goproxy.GoproxyCa
	}
	mitm.Configure(p, ca)

	pm := plugin.NewManager()

	// Configure Bandwidth Limiter
	var l *bandwidth.Limiter
	if cfg.BandwidthLimit > 0 {
		l = bandwidth.NewLimiter(cfg.BandwidthLimit, int(cfg.BandwidthLimit))
	}

	// Configure ICAP
	var icapClient *icap.Client
	if cfg.IcapUrl != "" {
		icapClient = icap.NewClient(cfg.IcapUrl)
	}

	// Configure DLP
	var dlpScanner *dlp.RegexScanner
	if len(cfg.DlpPatterns) > 0 {
		var err error
		dlpScanner, err = dlp.NewRegexScanner(cfg.DlpPatterns)
		if err != nil {
			logging.Logger.Error("Failed to compile DLP patterns", zap.Error(err))
		}
	}

	// Configure Scripting
	var scriptEngine engine.Engine
	if cfg.ScriptFile != "" {
		var err error
		if strings.HasSuffix(cfg.ScriptFile, ".star") {
			scriptEngine, err = starlark.NewEngine(cfg.ScriptFile)
		} else {
			scriptEngine, err = tengo.NewEngine(cfg.ScriptFile)
		}
		if err != nil {
			logging.Logger.Error("Failed to load script engine", zap.Error(err))
		}
	}

	// Start Hot-Reload Watcher if script is present
	if cfg.ScriptFile != "" {
		// We can't call s.StartHotReloadWatcher here because s isn't created yet.
		// We'll defer it to after s is created.
	}

	// Configure Auth
	authenticator, err := auth.NewAuthenticator(cfg.Auth, logging.Logger)
	if err != nil {
		logging.Logger.Error("Failed to initialize authenticator", zap.Error(err))
	}

	// Configure Threat Intel
	// Configure Threat Intel
	var threatMgr *threat.Manager
	if cfg.ThreatFile != "" || (cfg.DNSScience != nil && cfg.DNSScience.Enabled) {
		threatMgr = threat.NewManager()

		// Load local file
		if cfg.ThreatFile != "" {
			if err := threatMgr.LoadFromFile(cfg.ThreatFile); err != nil {
				logging.Logger.Error("Failed to load threat file", zap.Error(err))
			}
			// In a real app we'd start auto-reload here
		}

		// Load DNS Science
		if cfg.DNSScience != nil && cfg.DNSScience.Enabled {
			interval := 1 * time.Hour // Default
			if cfg.DNSScience.RefreshInterval != "" {
				if d, err := time.ParseDuration(cfg.DNSScience.RefreshInterval); err == nil {
					interval = d
				}
			}
			threatMgr.StartDNSScienceSync(cfg.DNSScience.FeedURL, cfg.DNSScience.APIKey, interval)

			// Initialize gRPC Client if configured
			if cfg.DNSScience.RPCAddr != "" {
				client, err := dnscache.NewClient(cfg.DNSScience.RPCAddr)
				if err != nil {
					logging.Logger.Error("Failed to connect to DNS Science gRPC", zap.Error(err))
				} else {
					threatMgr.SetDNSClient(client)
					logging.Logger.Info("Connected to DNS Science gRPC", zap.String("addr", cfg.DNSScience.RPCAddr))
				}
			}
		}
	}

	// Configure WAF
	wafScanner := waf.NewScanner()
	// could load custom rules here

	// Configure GeoIP
	var geoLookup *geoip.Lookup
	if cfg.GeoIPDBFile != "" {
		var err error
		geoLookup, err = geoip.NewLookup(cfg.GeoIPDBFile)
		if err != nil {
			logging.Logger.Error("Failed to load GeoIP DB", zap.Error(err))
		}
	}

	// Configure Cache
	cacheMgr := cache.NewManager(cfg.Redis)

	apiServer := api.NewServer(cfg, l)

	s := &Server{
		cfg:           cfg,
		proxy:         p,
		pm:            pm,
		apiServer:     apiServer,
		limiter:       l,
		icapClient:    icapClient,
		dlpScanner:    dlpScanner,
		wafScanner:    wafScanner,
		threatMgr:     threatMgr,
		geoIP:         geoLookup,
		scriptEngine:  scriptEngine,
		authenticator: authenticator,
		cache:         cacheMgr,
	}

	// Start Hot-Reload Watcher
	if cfg.ScriptFile != "" {
		s.StartHotReloadWatcher(cfg.ScriptFile)
	}

	// Build Middleware Chain
	s.middleware = []RequestMiddleware{}

	// 1. Threat Intel (IP/Domain) - Fastest/Critical
	if s.threatMgr != nil {
		s.middleware = append(s.middleware, s.middlewareThreatIntel)
	}

	// 2. GeoIP - Fast metadata check
	if s.geoIP != nil {
		s.middleware = append(s.middleware, s.middlewareGeoIP)
	}

	// 3. Auth - Verify Identity
	if s.authenticator != nil {
		s.middleware = append(s.middleware, s.middlewareAuth)
	}

	// 4. WAF - Content Inspection
	if s.wafScanner != nil {
		s.middleware = append(s.middleware, s.middlewareWAF)
	}

	// Hook Processor
	p.OnRequest().DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		// Run Middleware Chain
		for _, mw := range s.middleware {
			r, resp := mw(req, ctx)
			if resp != nil {
				return r, resp
			}
			if r != nil {
				req = r
			}
		}

		// API GATEWAY MODE (Pre-check handled by GatewayHandler, but if we are here,
		// it might be a forward proxy request or fell through.
		// Since custom routing is handled in the http.Handler wrapper (GatewayHandler),
		// goproxy primarily sees forward proxy requests or those we let through.
		return req, nil
	})

	return s
}

// GatewayHandler wraps the Proxy and Reverse Proxy logic
func (s *Server) GatewayHandler(w http.ResponseWriter, r *http.Request) {
	// 1. Check if this is a Reverse Proxy Route
	for _, route := range s.cfg.Routes {
		if strings.HasPrefix(r.URL.Path, route.Path) {
			// Found a match - Acting as API Gateway
			target, err := url.Parse(route.Upstream)
			if err != nil {
				logging.Logger.Error("Invalid upstream URL", zap.String("upstream", route.Upstream))
				http.Error(w, "Bad Gateway", http.StatusBadGateway)
				return
			}

			// Simple Reverse Proxy
			proxy := httputil.NewSingleHostReverseProxy(target)

			// Apply Auth/RateLimit specific to this route here...
			// (Skipped for brevity, but would check s.authenticator / s.limiter)

			logging.Logger.Info("Gateway: Proxying request",
				zap.String("path", r.URL.Path),
				zap.String("upstream", route.Upstream))

			// Update Host header
			r.Host = target.Host
			proxy.ServeHTTP(w, r)
			return
		}
	}

	// 2. Fallback to Forward Proxy
	s.proxy.ServeHTTP(w, r)
}

func (s *Server) Serve(l net.Listener) error {
	logging.Logger.Info("Starting proxy server", zap.String("addr", l.Addr().String()))

	// Start Admin API
	s.apiServer.Start()

	// Wrap listener for visibility
	l = visibility.NewTrackedListener(l)

	// Start QUIC Server (HTTP/3) if enabled
	if s.cfg.EnableQUIC {
		go func() {
			logging.Logger.Info("Starting QUIC listener (HTTP/3)", zap.String("addr", s.cfg.Addr))
			// http3.Server listens on UDP
			h3Server := &http3.Server{
				Addr:    s.cfg.Addr,
				Handler: http.HandlerFunc(s.GatewayHandler), // Use Gateway Handler
			}
			if err := h3Server.ListenAndServe(); err != nil {
				logging.Logger.Error("QUIC server failed", zap.Error(err))
			}
		}()
	}

	// Use GatewayHandler instead of s.proxy directly
	s.httpServer = &http.Server{
		Handler: http.HandlerFunc(s.GatewayHandler),
	}
	return s.httpServer.Serve(l)
}

// Shutdown gracefully shuts down the proxy server
func (s *Server) Shutdown(ctx context.Context) error {
	if s.httpServer != nil {
		return s.httpServer.Shutdown(ctx)
	}
	return nil
}
