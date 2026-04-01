package examples

import (
	"net/http"
	"strings"
	"time"

	"ads-httpproxy/internal/plugin"
	"ads-httpproxy/pkg/logging"

	"go.uber.org/zap"
)

// LoggerPlugin logs all requests and responses
type LoggerPlugin struct {
	LogHeaders        bool
	LogBody           bool
	SensitiveHeaders  []string // Headers to redact (e.g., Authorization, Cookie)
}

func NewLoggerPlugin(logHeaders, logBody bool) *LoggerPlugin {
	return &LoggerPlugin{
		LogHeaders: logHeaders,
		LogBody:    logBody,
		SensitiveHeaders: []string{
			"authorization",
			"cookie",
			"set-cookie",
			"proxy-authorization",
			"www-authenticate",
			"x-api-key",
			"x-auth-token",
		},
	}
}

func (p *LoggerPlugin) Name() string {
	return "logger"
}

func (p *LoggerPlugin) OnRequest(req *http.Request, ctx *plugin.Context) (*http.Request, *http.Response) {
	if req == nil {
		return req, nil
	}

	fields := []zap.Field{
		zap.String("method", req.Method),
		zap.String("url", req.URL.String()),
		zap.String("host", req.Host),
		zap.String("remote_addr", req.RemoteAddr),
		zap.Time("timestamp", time.Now()),
	}

	if p.LogHeaders && req.Header != nil {
		headers := p.sanitizeHeaders(req.Header)
		fields = append(fields, zap.Any("headers", headers))
	}

	logging.Logger.Info("Plugin: Request", fields...)
	return req, nil
}

// sanitizeHeaders redacts sensitive header values
func (p *LoggerPlugin) sanitizeHeaders(headers http.Header) map[string][]string {
	sanitized := make(map[string][]string)
	for k, v := range headers {
		isSensitive := false
		for _, sensitive := range p.SensitiveHeaders {
			if strings.EqualFold(k, sensitive) {
				isSensitive = true
				break
			}
		}
		if isSensitive {
			sanitized[k] = []string{"[REDACTED]"}
		} else {
			sanitized[k] = v
		}
	}
	return sanitized
}

func (p *LoggerPlugin) OnResponse(resp *http.Response, ctx *plugin.Context) *http.Response {
	if resp == nil {
		return resp
	}

	fields := []zap.Field{
		zap.Int("status_code", resp.StatusCode),
		zap.String("status", resp.Status),
		zap.Int64("content_length", resp.ContentLength),
		zap.Time("timestamp", time.Now()),
	}

	if p.LogHeaders && resp.Request != nil {
		fields = append(fields,
			zap.String("url", resp.Request.URL.String()),
		)

		if resp.Header != nil {
			headers := p.sanitizeHeaders(resp.Header)
			fields = append(fields, zap.Any("response_headers", headers))
		}
	}

	logging.Logger.Info("Plugin: Response", fields...)
	return resp
}
