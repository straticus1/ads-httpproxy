package proxy

import (
	"net"
	"net/http"

	"ads-httpproxy/internal/api"
	"ads-httpproxy/internal/bandwidth"
	"ads-httpproxy/internal/config"
	"ads-httpproxy/internal/dlp"
	"ads-httpproxy/internal/icap"
	"ads-httpproxy/internal/mitm"
	"ads-httpproxy/internal/plugin"
	"ads-httpproxy/internal/scripting/engine"
	"ads-httpproxy/internal/scripting/tengo"
	"ads-httpproxy/internal/visibility"
	"ads-httpproxy/pkg/logging"

	"github.com/elazarl/goproxy"
	"go.uber.org/zap"
)

type Server struct {
	cfg          *config.Config
	proxy        *goproxy.ProxyHttpServer
	pm           *plugin.Manager
	apiServer    *api.Server
	limiter      *bandwidth.Limiter
	icapClient   *icap.Client
	dlpScanner   *dlp.RegexScanner
	scriptEngine engine.Engine
}

func NewServer(cfg *config.Config) *Server {
	p := goproxy.NewProxyHttpServer()
	p.Verbose = true // Enable verbose logging for now

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
		scriptEngine, err = tengo.NewEngine(cfg.ScriptFile)
		if err != nil {
			logging.Logger.Error("Failed to load script engine", zap.Error(err))
		}
	}

	apiServer := api.NewServer(cfg, l)

	s := &Server{
		cfg:          cfg,
		proxy:        p,
		pm:           pm,
		apiServer:    apiServer,
		limiter:      l,
		icapClient:   icapClient,
		dlpScanner:   dlpScanner,
		scriptEngine: scriptEngine,
	}

	// Hook Plugin Manager & Visibility & Bandwidth & ICAP & DLP & Scripting
	p.OnRequest().DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		visibility.IncTotalRequests()

		// Bandwidth Limiter for Request Body (Upload)
		if s.limiter != nil && req.Body != nil {
			req.Body = &bandwidth.LimitedReadCloser{RC: req.Body, Limiter: s.limiter}
		}

		// Script Engine OnRequest
		if s.scriptEngine != nil {
			if err := s.scriptEngine.OnRequest(req.Context(), req); err != nil {
				logging.Logger.Info("Request blocked by policy script", zap.String("url", req.URL.String()))
				return req, goproxy.NewResponse(req, goproxy.ContentTypeText, http.StatusForbidden, "Blocked by policy")
			}
		}

		// DLP Scanning (Basic: Request Headers/Body?)
		// For now, we only scan if body is small or we assume stream scanning (which requires wrapping).
		// Since we don't have a streaming DLP scanner yet, we'll skip complex body scanning here to avoid buffering.
		// Future: Wrap Body with DLP Scanning Reader.

		// ICAP REQMOD
		if s.icapClient != nil {
			modReq, err := s.icapClient.ReqMod(req)
			if err != nil {
				logging.Logger.Error("ICAP REQMOD failed", zap.Error(err))
				// Fail open or closed? Open for now.
			} else if modReq != nil {
				req = modReq
			}
		}

		pCtx := &plugin.Context{} // Map state if needed
		return pm.HandleRequest(req, pCtx)
	})

	p.OnResponse().DoFunc(func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
		// Bandwidth Limiter for Response Body (Download)
		if s.limiter != nil && resp.Body != nil {
			resp.Body = &bandwidth.LimitedReadCloser{RC: resp.Body, Limiter: s.limiter}
		}

		// Script Engine OnResponse (optional, not blocking usually unless we want filter response)

		// ICAP RESPMOD
		if s.icapClient != nil {
			modResp, err := s.icapClient.RespMod(resp)
			if err != nil {
				logging.Logger.Error("ICAP RESPMOD failed", zap.Error(err))
			} else if modResp != nil {
				resp = modResp
			}
		}

		pCtx := &plugin.Context{}
		return pm.HandleResponse(resp, pCtx)
	})

	return s
}

func (s *Server) Serve(l net.Listener) error {
	logging.Logger.Info("Starting proxy server", zap.String("addr", l.Addr().String()))

	// Start Admin API
	s.apiServer.Start()

	// Wrap listener for visibility
	l = visibility.NewTrackedListener(l)

	return http.Serve(l, s.proxy)
}
