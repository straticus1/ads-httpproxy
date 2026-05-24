package proxy

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"strings"

	"ads-httpproxy/internal/api"
	"ads-httpproxy/internal/auth"
	"ads-httpproxy/internal/bandwidth"
	"ads-httpproxy/internal/browserid"
	"ads-httpproxy/internal/ja3"
	"ads-httpproxy/internal/cache"
	"ads-httpproxy/internal/config"
	"ads-httpproxy/internal/dlp"
	"ads-httpproxy/internal/geoip"
	"ads-httpproxy/internal/icap"
	"ads-httpproxy/internal/masque"
	"ads-httpproxy/internal/mitm"
	"ads-httpproxy/internal/ml"
	"ads-httpproxy/internal/peering"
	"ads-httpproxy/internal/plugin"
	"ads-httpproxy/internal/policy"
	"ads-httpproxy/internal/telemetry"
	"ads-httpproxy/internal/reputation"
	"ads-httpproxy/internal/screenshot"
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
	"golang.org/x/crypto/acme/autocert"
)

type RequestMiddleware func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response)
type ResponseMiddleware func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response

var proxyBufferPool = &sync.Pool{
	New: func() interface{} {
		return make([]byte, 32*1024)
	},
}

type bufferPoolAdapter struct{}

func (b bufferPoolAdapter) Get() []byte {
	return proxyBufferPool.Get().([]byte)
}

func (b bufferPoolAdapter) Put(bytes []byte) {
	proxyBufferPool.Put(bytes)
}

type Server struct {
	cfg            *config.Config
	proxy          *goproxy.ProxyHttpServer
	pm             *plugin.Manager
	apiServer      *api.Server
	limiter        bandwidth.Limiter
	icapClient     *icap.Cluster
	dlpScanner     *dlp.VisualDLP
	wafEngine      *waf.Engine
	threatMgr      *threat.Manager
	geoIP          *geoip.Lookup
	scriptEngine   engine.Engine
	policyEngine   *policy.Engine
	peerMgr        *peering.PeerManager
	reputation     *reputation.Client
	feedManager    *reputation.FeedManager
	authenticator  auth.Authenticator
	httpCache      *cache.HTTPCache
	screenshot     *screenshot.Service
	httpServer     *http.Server
	middleware     []RequestMiddleware
	respMiddleware []ResponseMiddleware
	compiledRoutes []PreparedRoute // Legacy simple routes
	compiledApps   map[string]*PreparedApp
	certManager    *autocert.Manager
	upstreamMgr    *UpstreamManager
	anomalyMonitor *ml.AnomalyMonitor
}

type PreparedAppRoute struct {
	Config config.AppRoute
	Proxy  *httputil.ReverseProxy
}

type PreparedApp struct {
	Config config.AppConfig
	Routes []PreparedAppRoute
}

type PreparedRoute struct {
	Path       string
	Upstream   *url.URL
	Proxy      *httputil.ReverseProxy
	RateLimit  int
	AuthMethod string
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

	// Load plugins if configured
	if cfg.Plugins != nil && cfg.Plugins.Enabled {
		loader := plugin.NewLoader(pm)

		// Load specific plugins from list
		if len(cfg.Plugins.PluginList) > 0 {
			for _, pluginFile := range cfg.Plugins.PluginList {
				if err := loader.LoadFromFile(pluginFile); err != nil {
					logging.Logger.Error("Failed to load plugin", zap.String("file", pluginFile), zap.Error(err))
				}
			}
		}

		// Auto-load from directory
		if cfg.Plugins.AutoLoad && cfg.Plugins.PluginDir != "" {
			if err := loader.LoadFromDirectory(cfg.Plugins.PluginDir); err != nil {
				logging.Logger.Error("Failed to load plugins from directory", zap.String("dir", cfg.Plugins.PluginDir), zap.Error(err))
			}
		}
	}

	// Configure Bandwidth Limiter
	var l bandwidth.Limiter // Interface type
	if cfg.BandwidthLimit > 0 {
		l = bandwidth.NewLocalLimiter(cfg.BandwidthLimit, int(cfg.BandwidthLimit))
	}

	// Configure ICAP
	var icapClient *icap.Cluster
	if len(cfg.IcapUrls) > 0 {
		icapClient = icap.NewCluster(cfg.IcapUrls)
	}

	// Configure DLP
	// Configure DLP
	var dlpScanner *dlp.VisualDLP
	if len(cfg.DlpPatterns) > 0 {
		var err error
		// TODO: Pass actual service URLs from config
		dlpScanner, err = dlp.NewVisualDLP(cfg.DlpPatterns, "http://localhost:8081", "http://localhost:8082", cfg.DlpReportFile, int64(cfg.MaxArchiveUnpackSize))
		if err != nil {
			logging.Logger.Error("Failed to compile DLP patterns", zap.Error(err))
		}
	}

	// Configure Scripting (must be declared after threatMgr)
	var scriptEngine engine.Engine
	// scriptEngine initialization moved after threatMgr is fully initialized

	// Configure Policy Engine
	policyEngine, err := policy.NewEngine()
	if err != nil {
		logging.Logger.Error("Failed to create policy engine", zap.Error(err))
	}
	// TODO: Implement LoadFromFile for policy engine
	if cfg.PolicyFile != "" {
		logging.Logger.Warn("Policy file loading not yet implemented", zap.String("file", cfg.PolicyFile))
	}

	// Configure Peering
	peerMgr, err := peering.NewManager(cfg.Peering)
	if err != nil {
		logging.Logger.Error("Failed to initialize peering", zap.Error(err))
	}

	// Start Hot-Reload Watcher if script is present
	if cfg.ScriptFile != "" {
		// We can't call s.StartHotReloadWatcher here because s isn't created yet.
		// We'll defer it to after s is created.
	}

	// Configure Auth. NewAuthenticator always returns a non-nil authenticator:
	// when mechanism="none" and allow_unauthenticated=false it returns a
	// DenyAllAuthenticator, preventing accidental open-relay deployment.
	authenticator, err := auth.NewAuthenticator(cfg.Auth, logging.Logger)
	if err != nil {
		logging.Logger.Fatal("Failed to initialize authenticator", zap.Error(err))
	}

	// Configure Reputation Service
	var repClient *reputation.Client
	var feedMgr *reputation.FeedManager
	if cfg.Reputation != nil && cfg.Reputation.Enabled {
		repClient = reputation.NewClient(
			cfg.Reputation.URL,
			cfg.Reputation.Timeout,
			cfg.Reputation.FailOpen,
		)
		logging.Logger.Info("Reputation Service Enabled", zap.String("url", cfg.Reputation.URL))

		// Initialize URL Reputation Feeds
		if cfg.Reputation.Feeds != nil && cfg.Reputation.Feeds.Enabled {
			feedMgr = reputation.NewFeedManager()
			feedMgr.InitDefaultFeeds()

			// Configure which default feeds to enable
			for i := range feedMgr.Sources {
				src := &feedMgr.Sources[i]
				switch src.Name {
				case "URLhaus":
					src.Enabled = cfg.Reputation.Feeds.EnableURLhaus
				case "PhishTank":
					src.Enabled = cfg.Reputation.Feeds.EnablePhishTank
				case "OpenPhish":
					src.Enabled = cfg.Reputation.Feeds.EnableOpenPhish
				case "ThreatFox":
					src.Enabled = cfg.Reputation.Feeds.EnableThreatFox
				}

				if cfg.Reputation.Feeds.UpdateInterval > 0 {
					src.UpdateFreq = time.Duration(cfg.Reputation.Feeds.UpdateInterval) * time.Minute
				}
			}

			// Add custom feeds
			for _, customFeed := range cfg.Reputation.Feeds.CustomFeeds {
				parser := &reputation.PlaintextParser{
					Category: customFeed.Category,
					Score:    85,
				}
				if customFeed.Type == "csv" {
					// Would need specific parser based on format
					parser = &reputation.PlaintextParser{Category: customFeed.Category, Score: 85}
				}

				feedMgr.AddCustomFeed(reputation.FeedSource{
					Name:       customFeed.Name,
					URL:        customFeed.URL,
					Type:       customFeed.Type,
					Category:   customFeed.Category,
					UpdateFreq: time.Duration(cfg.Reputation.Feeds.UpdateInterval) * time.Minute,
					Enabled:    true,
					Parser:     parser,
				})
			}

			// Start syncing feeds
			go feedMgr.StartSync(context.Background())

			// Start cleanup routine
			if cfg.Reputation.Feeds.MaxAge > 0 {
				maxAge := time.Duration(cfg.Reputation.Feeds.MaxAge) * 24 * time.Hour
				go func() {
					ticker := time.NewTicker(24 * time.Hour)
					defer ticker.Stop()
					for range ticker.C {
						feedMgr.Cleanup(maxAge)
					}
				}()
			}

			logging.Logger.Info("URL Reputation Feeds Enabled",
				zap.Bool("urlhaus", cfg.Reputation.Feeds.EnableURLhaus),
				zap.Bool("phishtank", cfg.Reputation.Feeds.EnablePhishTank),
				zap.Bool("openphish", cfg.Reputation.Feeds.EnableOpenPhish),
				zap.Bool("threatfox", cfg.Reputation.Feeds.EnableThreatFox),
				zap.Int("custom_feeds", len(cfg.Reputation.Feeds.CustomFeeds)))
		}
	}

	// Configure Threat Intel
	// Configure Threat Intel
	var threatMgr *threat.Manager
	if cfg.ThreatFile != "" || (cfg.DNSScience != nil && cfg.DNSScience.Enabled) || len(cfg.ThreatSources) > 0 {
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

			// Combine DNS Science Feed options
			sources := cfg.ThreatSources
			if cfg.DNSScience.FeedURL != "" {
				sources = append(sources, cfg.DNSScience.FeedURL)
			}

			threatMgr.StartSync(sources, interval)

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
		} else if len(cfg.ThreatSources) > 0 {
			// Sync generic sources even if DNSScience specific features (like gRPC) are disabled
			threatMgr.StartSync(cfg.ThreatSources, 1*time.Hour)
		}
	}

	// Configure WAF
	var wafEngine *waf.Engine
	if cfg.WAF != nil && cfg.WAF.Enabled {
		var maxBody int64
		if cfg.WAF.MaxBodySizeMB > 0 {
			maxBody = int64(cfg.WAF.MaxBodySizeMB) << 20
		}
		var wafErr error
		wafEngine, wafErr = waf.NewEngine(&waf.Config{
			DetectionOnly:    cfg.WAF.DetectionOnly,
			ParanoiaLevel:    cfg.WAF.ParanoiaLevel,
			AnomalyThreshold: cfg.WAF.AnomalyThreshold,
			ExcludedRules:    cfg.WAF.ExcludedRules,
			MaxBodySize:      maxBody,
			EventLogFile:     cfg.WAF.EventLogFile,
			CustomRulesDir:   cfg.WAF.CustomRulesDir,
		})
		if wafErr != nil {
			logging.Logger.Fatal("Failed to init WAF engine", zap.Error(wafErr))
		}
		logging.Logger.Info("WAF engine started",
			zap.Int("paranoia_level", cfg.WAF.ParanoiaLevel),
			zap.Int("anomaly_threshold", cfg.WAF.AnomalyThreshold),
			zap.Bool("detection_only", cfg.WAF.DetectionOnly),
		)
	}

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

	// Configure HTTP Cache (L1 + L2 caching)
	var httpCacheMgr *cache.HTTPCache
	if cfg.Cache != nil && cfg.Cache.Enabled {
		cacheConfig := &cache.CacheConfig{
			Enabled:         cfg.Cache.Enabled,
			MemoryEnabled:   cfg.Cache.Memory != nil && cfg.Cache.Memory.Enabled,
			MemoryMaxSizeMB: 500,
			MemoryMaxTTL:    60 * time.Second,
			DefaultTTL:      3600 * time.Second,
			MaxTTL:          86400 * time.Second,
			MinSizeBytes:    1024,
			MaxSizeBytes:    10 * 1024 * 1024,
			CompressBody:    true,
			CachePrivate:    false,
		}

		if cfg.Cache.Memory != nil {
			if cfg.Cache.Memory.MaxSizeMB > 0 {
				cacheConfig.MemoryMaxSizeMB = cfg.Cache.Memory.MaxSizeMB
			}
			if cfg.Cache.Memory.MaxTTL > 0 {
				cacheConfig.MemoryMaxTTL = time.Duration(cfg.Cache.Memory.MaxTTL) * time.Second
			}
		}

		if cfg.Cache.DefaultTTL > 0 {
			cacheConfig.DefaultTTL = time.Duration(cfg.Cache.DefaultTTL) * time.Second
		}
		if cfg.Cache.MaxTTL > 0 {
			cacheConfig.MaxTTL = time.Duration(cfg.Cache.MaxTTL) * time.Second
		}

		httpCacheMgr = cache.NewHTTPCache(cacheMgr, cacheConfig)

		// Start memory cache cleanup if enabled
		if httpCacheMgr != nil && cacheConfig.MemoryEnabled {
			// Cleanup every 60 seconds
			go func() {
				ticker := time.NewTicker(60 * time.Second)
				defer ticker.Stop()
				for range ticker.C {
					if httpCacheMgr != nil {
						// Memory cleanup is handled internally
					}
				}
			}()
		}
	}

	// Configure Screenshot Service
	screenshotSvc := screenshot.NewService()

	// NOW Initialize Scripting Engine (threatMgr is ready)
	if cfg.ScriptFile != "" {
		var err error
		if strings.HasSuffix(cfg.ScriptFile, ".star") {
			scriptEngine, err = starlark.NewEngine(cfg.ScriptFile, threatMgr)
		} else {
			scriptEngine, err = tengo.NewEngine(cfg.ScriptFile)
		}
		if err != nil {
			logging.Logger.Error("Failed to load script engine", zap.Error(err))
		}
	}

	apiServer := api.NewServer(cfg, l, pm)

	// Set cache handler if cache is enabled
	if httpCacheMgr != nil {
		cacheHandler := api.NewCacheHandler(httpCacheMgr)
		apiServer.SetCacheHandler(cacheHandler)
	}

	// Configuration Upstream Manager
	um := NewUpstreamManager(cfg)

	// OpenTelemetry Tracing
	if _, err := telemetry.InitProvider(context.Background(), "ads-httpproxy"); err != nil {
		logging.Logger.Warn("OpenTelemetry tracing failed to start", zap.Error(err))
	}

	s := &Server{
		cfg:           cfg,
		proxy:         p,
		pm:            pm,
		apiServer:     apiServer,
		limiter:       l,
		icapClient:    icapClient,
		dlpScanner:    dlpScanner,
		wafEngine:     wafEngine,
		threatMgr:     threatMgr,
		geoIP:         geoLookup,
		scriptEngine:  scriptEngine,
		policyEngine:  policyEngine,
		peerMgr:       peerMgr,
		reputation:    repClient,
		feedManager:   feedMgr,
		authenticator: authenticator,
		httpCache:     httpCacheMgr,
		screenshot:    screenshotSvc,
		upstreamMgr:   um,
		anomalyMonitor: ml.NewAnomalyMonitor(),
	}

	if s.peerMgr != nil {
		s.peerMgr.SetCache(httpCacheMgr)
	}

	// Setup Let's Encrypt Manager
	if cfg.AutoCertCacheDir != "" {
		s.certManager = &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			Cache:      autocert.DirCache(cfg.AutoCertCacheDir),
			HostPolicy: s.autocertHostPolicy,
		}
	}

	// Pre-compile App Routes
	s.compiledApps = make(map[string]*PreparedApp)
	for _, appCfg := range cfg.Apps {
		a := &PreparedApp{
			Config: *appCfg,
		}
		for _, r := range appCfg.Routes {
			upstreamName := r.Upstream
			proxy := &httputil.ReverseProxy{
				Director: func(req *http.Request) {
					target, err := um.GetTarget(upstreamName)
					if err != nil {
						logging.Logger.Error("Failed to resolve app upstream", zap.Error(err))
						return
					}
					req.URL.Scheme = target.Scheme
					req.URL.Host = target.Host
					
					// Rewrite Path logic
					if r.PathRewrite != "" {
						req.URL.Path = r.PathRewrite
					} else if r.PathStrip != "" {
						req.URL.Path = strings.TrimPrefix(req.URL.Path, r.PathStrip)
					}
					
					// Prepend target path if there is one
					if target.Path != "" && target.Path != "/" {
						req.URL.Path = target.Path + req.URL.Path
					}

					req.Host = target.Host // Forward correct Host to upstream
					if _, ok := req.Header["User-Agent"]; !ok {
						req.Header.Set("User-Agent", "")
					}
				},
			}
			proxy.BufferPool = bufferPoolAdapter{}
			proxy.FlushInterval = -1
			a.Routes = append(a.Routes, PreparedAppRoute{
				Config: r,
				Proxy:  proxy,
			})
		}
		for _, domain := range appCfg.Domains {
			s.compiledApps[domain] = a
		}
	}

	// Pre-compile Legacy Routes O(N) at startup, O(1) allocation at runtime
	s.compiledRoutes = make([]PreparedRoute, 0, len(cfg.Routes))
	for _, r := range cfg.Routes {
		upstreamName := r.Upstream // Capture for closure
		chainName := r.Chain       // Capture for closure

		// Use UpstreamManager to validate/resolve initial target (or group check)
		initialTarget, err := um.GetTarget(upstreamName)
		if err != nil {
			logging.Logger.Error("Invalid upstream/group in route", zap.String("path", r.Path), zap.String("upstream", upstreamName), zap.Error(err))
			continue
		}

		// Create Reverse Proxy with Dynamic Director for Group Support
		proxy := &httputil.ReverseProxy{
			Director: func(req *http.Request) {
				// Resolve Target Dynamically (LB / Failover)
				target, err := um.GetTarget(upstreamName)
				if err != nil {
					logging.Logger.Error("Failed to resolve upstream", zap.Error(err))
					return
				}
				req.URL.Scheme = target.Scheme
				req.URL.Host = target.Host
				req.Host = target.Host // Force Host header to upstream
				if _, ok := req.Header["User-Agent"]; !ok {
					// explicitly disable User-Agent so it's not set to default value
					req.Header.Set("User-Agent", "")
				}
			},
		}

		proxy.BufferPool = bufferPoolAdapter{}

		// Configure Transport (Chaining / Tuning)
		if chainName != "" {
			transport, err := um.Transport(chainName)
			if err != nil {
				logging.Logger.Error("Invalid chain in route", zap.String("chain", chainName), zap.Error(err))
				continue
			}
			proxy.Transport = transport
		} else {
			// standard transport optimizations
			// FlushInterval -1 means flush immediately after each write (Essential for gRPC/Streaming)
			proxy.FlushInterval = -1
		}

		s.compiledRoutes = append(s.compiledRoutes, PreparedRoute{
			Path:       r.Path,
			Upstream:   initialTarget, // Stored for metadata/logging
			Proxy:      proxy,
			RateLimit:  r.RateLimit,
			AuthMethod: r.AuthMethod,
		})
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

	// 3. Auth — always enforced. The authenticator is never nil: when no
	// mechanism is configured, a DenyAllAuthenticator blocks all traffic
	// unless allow_unauthenticated is explicitly set in the config.
	s.middleware = append(s.middleware, s.middlewareAuth)

	// 4. HTTP Cache Check (After auth, before expensive operations)
	if s.httpCache != nil {
		s.middleware = append(s.middleware, s.middlewareCache)
	}

	// 5. Policy Engine (Needs User/Time/Geo context)
	if s.policyEngine != nil {
		s.middleware = append(s.middleware, s.middlewarePolicy)
	}

	// 6. Reputation Service (Check External Reputation)
	if s.reputation != nil {
		s.middleware = append(s.middleware, s.middlewareReputation)
	}

	// 6. Peering (Check parents/siblings before going upstream)
	if s.peerMgr != nil {
		s.middleware = append(s.middleware, s.middlewarePeering)
	}

	// 6. WAF - Content Inspection
	if s.wafEngine != nil {
		s.middleware = append(s.middleware, s.middlewareWAF)
	}

	// 7. DLP (Request)
	if s.dlpScanner != nil {
		s.middleware = append(s.middleware, s.middlewareDLP)
	}

	// 8. ICAP (ReqMod)
	if s.icapClient != nil {
		s.middleware = append(s.middleware, s.middlewareICAP)
	}

	// 9. Bandwidth Limiter (Request) — wraps the request body so each byte
	// consumed by the upstream read is throttled to cfg.BandwidthLimit bytes/sec.
	if s.limiter != nil {
		s.middleware = append(s.middleware, func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
			if req.Body != nil {
				req.Body = &bandwidth.LimitedReadCloser{
					RC:      req.Body,
					Limiter: s.limiter,
					Ctx:     req.Context(),
				}
			}
			return req, nil
		})
	}

	// 10. Plugin System (Request) - Last before upstream
	s.middleware = append(s.middleware, s.middlewarePlugins)

	// Build Response Middleware Chain
	s.respMiddleware = []ResponseMiddleware{}

	// 1. DLP (Response)
	if s.dlpScanner != nil {
		s.respMiddleware = append(s.respMiddleware, s.middlewareRespDLP)
	}

	// 2. ICAP (RespMod)
	if s.icapClient != nil {
		s.respMiddleware = append(s.respMiddleware, s.middlewareRespICAP)
	}

	// 3. HTTP Cache Store (Store responses in cache)
	if s.httpCache != nil {
		s.respMiddleware = append(s.respMiddleware, s.middlewareRespCache)
	}

	// 4. Plugin System (Response) - Last before client
	s.respMiddleware = append(s.respMiddleware, s.middlewareRespPlugins)

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

	p.OnResponse().DoFunc(func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
		for _, mw := range s.respMiddleware {
			resp = mw(resp, ctx)
			if resp == nil {
				return nil
			}
		}
		return resp
	})

	return s
}

// GatewayHandler is the main HTTP handler for reverse proxy routes
func (s *Server) GatewayHandler(w http.ResponseWriter, r *http.Request) {
	// Start OTel Trace Span
	tracer := telemetry.GetTracer("ads-httpproxy.gateway")
	ctx, span := tracer.Start(r.Context(), r.URL.Path)
	defer span.End()
	r = r.WithContext(ctx)

	if s.cfg.Features != nil && s.cfg.Features.MASQUE {
		if r.Method == "CONNECT-UDP" {
			masque.HandleUDP(w, r)
			return
		}
		if r.Method == "CONNECT-IP" {
			masque.HandleIP(w, r)
			return
		}
	}

	handler := func(w http.ResponseWriter, r *http.Request) {
		// L7 Application Edge Routing
		if app, ok := s.compiledApps[r.Host]; ok {
			// App matches, route it by L7 paths
			for _, route := range app.Routes {
				if strings.HasPrefix(r.URL.Path, route.Config.PathRoute) {
					// We matched! 
					// Enforce application-specific WAF natively
					if app.Config.WAF && s.wafEngine != nil {
						result, err := s.wafEngine.Check(r)
						if err != nil {
							logging.Logger.Error("WAF check error", zap.Error(err))
						} else if result.Blocked {
							logging.Logger.Warn("WAF blocked request to App",
								zap.String("host", r.Host),
								zap.String("path", r.URL.Path),
								zap.Int("rule_id", result.RuleID),
							)
							http.Error(w, "Forbidden", http.StatusForbidden)
							return
						}
					}
					
					// Proxy Execute or WebSocket Hijack
					logging.Logger.Info("App Route Matched", zap.String("app", r.Host), zap.String("route", route.Config.PathRoute))
					
					if strings.ToLower(r.Header.Get("Connection")) == "upgrade" && strings.ToLower(r.Header.Get("Upgrade")) == "websocket" {
						// Retrieve assigned UPSTREAM from proxy Director modification loop via a dummy copy
						target, _ := s.upstreamMgr.GetTarget(route.Config.Upstream)
						if target != nil {
							HandleWebSocket(w, r, target)
							return
						}
					}
					
					route.Proxy.ServeHTTP(w, r)
					return
				}
			}
			
			// App configured for this Host, but no route handled it -> Block to prevent bleed into default forwards
			http.Error(w, "Not Found", http.StatusNotFound)
			return
		}

		// 1. Check if this is a Reverse Proxy Route (Legacy System)
		// Optimization: Routes are pre-compiled in NewServer.
		if s.cfg.Features != nil && s.cfg.Features.ReverseProxy {
			for _, route := range s.compiledRoutes {
			if strings.HasPrefix(r.URL.Path, route.Path) {
				
				var clientIP string
				if ident, ok := r.Context().Value(browserid.IdentityContextKey).(*browserid.Identity); ok && ident != nil {
					clientIP = ident.IP
				} else {
					clientIP, _, _ = net.SplitHostPort(r.RemoteAddr)
					if clientIP == "" {
						clientIP = r.RemoteAddr
					}
				}

				// Check Threat Intel for Reverse Proxy Client
				if s.threatMgr != nil {
					if blocked := s.threatMgr.IsBlocked(clientIP); blocked {
						logging.Logger.Warn("Blocked reverse proxy access from threat IP", zap.String("ip", clientIP))
						http.Error(w, "Forbidden - IP Blocked", http.StatusForbidden)
						return
					}
				}

				// ML Anomaly Detection tracking
				if s.anomalyMonitor != nil {
					s.anomalyMonitor.Track(clientIP)
				}

				// Gateway Logic: Rate Limit & Auth
				// 1. Rate Limit (Global for route for now)
				if s.limiter != nil {
					if err := s.limiter.WaitN(r.Context(), 1); err != nil {
						http.Error(w, "Rate Limit Exceeded", http.StatusTooManyRequests)
						return
					}
				}

				// 2. Auth Pipeline (Execute Native Authenticator on Gateway Route)
				if route.AuthMethod != "" && route.AuthMethod != "none" {
					if s.authenticator != nil {
						authenticated, user, challenge, err := s.authenticator.Authenticate(r)
						if err != nil {
							logging.Logger.Error("Gateway authentication error", zap.Error(err))
							http.Error(w, "Internal Server Error", http.StatusInternalServerError)
							return
						}
						if !authenticated {
							if challenge == "" {
								challenge, _ = s.authenticator.Challenge(r)
							}
							if challenge != "" {
								w.Header().Set("WWW-Authenticate", challenge)
								w.Header().Set("Proxy-Authenticate", challenge)
							}
							http.Error(w, "Unauthorized", http.StatusUnauthorized)
							return
						}
						// Fast-path user identity propagation to upstream
						r.Header.Set("X-Authenticated-User", user)
					} else {
						// Fallback to basic header existence check if authenticator is somehow nil
						if r.Header.Get("Authorization") == "" {
							http.Error(w, "Unauthorized", http.StatusUnauthorized)
							return
						}
					}
				}

				logging.Logger.Info("Gateway: Proxying request",
					zap.String("path", r.URL.Path),
					zap.String("upstream", route.Upstream.String()))

				// Update Host header
				r.Host = route.Upstream.Host

				// Hook WebSocket Support for Legacy Routing
				if strings.ToLower(r.Header.Get("Connection")) == "upgrade" && strings.ToLower(r.Header.Get("Upgrade")) == "websocket" {
					HandleWebSocket(w, r, route.Upstream)
					return
				}

				route.Proxy.ServeHTTP(w, r)
				return
			}
		}
		}

		// 2. Fallback to Forward Proxy
		s.proxy.ServeHTTP(w, r)
	}

	if s.cfg.Features != nil && s.cfg.Features.BrowserID {
		browserid.Middleware(handler)(w, r)
	} else {
		handler(w, r)
	}
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
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			if sc, ok := c.(*ja3.SniffedConn); ok {
				return context.WithValue(ctx, "ja3_conn", sc)
			}
			return ctx
		},
	}

	if s.certManager != nil {
		// Attach autocert to httpServer's TLS config
		s.httpServer.TLSConfig = s.certManager.TLSConfig()
	}

	return s.httpServer.Serve(l)
}

func (s *Server) Shutdown(ctx context.Context) error {
	if s.peerMgr != nil {
		s.peerMgr.Shutdown(ctx)
	}
	if s.httpServer != nil {
		return s.httpServer.Shutdown(ctx)
	}
	return nil
}

// autocertHostPolicy defines which domains the proxy is allowed to request ACME certificates for.
func (s *Server) autocertHostPolicy(ctx context.Context, host string) error {
	// Look for the host in our compiledApps map
	// If it exists AND is marked AutoCert = true, allow it.
	if app, ok := s.compiledApps[host]; ok && app.Config.AutoCert {
		return nil
	}
	return fmt.Errorf("autocert: host %s not configured for auto-cert in ads-httpproxy", host)
}
