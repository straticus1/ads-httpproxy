package examples

import (
	"net/http"
	"time"

	"ads-httpproxy/internal/plugin"
	"ads-httpproxy/pkg/logging"

	"go.uber.org/zap"
)

// LoggerPlugin logs all requests and responses
type LoggerPlugin struct {
	LogHeaders bool
	LogBody    bool
}

func NewLoggerPlugin(logHeaders, logBody bool) *LoggerPlugin {
	return &LoggerPlugin{
		LogHeaders: logHeaders,
		LogBody:    logBody,
	}
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

		headers := make(map[string][]string)
		for k, v := range resp.Header {
			headers[k] = v
		}
		fields = append(fields, zap.Any("response_headers", headers))
	}

	logging.Logger.Info("Plugin: Response", fields...)
	return resp
}
