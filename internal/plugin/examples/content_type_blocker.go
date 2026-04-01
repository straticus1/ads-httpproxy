package examples

import (
	"net/http"
	"strings"

	"ads-httpproxy/internal/plugin"
	"ads-httpproxy/pkg/logging"

	"github.com/elazarl/goproxy"
	"go.uber.org/zap"
)

// ContentTypeBlockerPlugin blocks responses with specific content types
type ContentTypeBlockerPlugin struct {
	BlockedTypes []string // e.g., "application/x-executable", "application/pdf"
	BlockMessage string
}

func NewContentTypeBlockerPlugin(blockedTypes []string) *ContentTypeBlockerPlugin {
	return &ContentTypeBlockerPlugin{
		BlockedTypes: blockedTypes,
		BlockMessage: "Access Denied: Content Type Blocked",
	}
}

func (p *ContentTypeBlockerPlugin) Name() string {
	return "content-type-blocker"
}

func (p *ContentTypeBlockerPlugin) OnRequest(req *http.Request, ctx *plugin.Context) (*http.Request, *http.Response) {
	// No request filtering
	return req, nil
}

func (p *ContentTypeBlockerPlugin) OnResponse(resp *http.Response, ctx *plugin.Context) *http.Response {
	contentType := resp.Header.Get("Content-Type")
	if contentType == "" {
		return resp
	}

	// Check if content type is blocked
	for _, blocked := range p.BlockedTypes {
		if strings.Contains(strings.ToLower(contentType), strings.ToLower(blocked)) {
			logging.Logger.Warn("Plugin: Blocked content type",
				zap.String("plugin", p.Name()),
				zap.String("content_type", contentType),
				zap.String("url", resp.Request.URL.String()))

			// Create blocked response
			blockedResp := goproxy.NewResponse(resp.Request,
				goproxy.ContentTypeText,
				http.StatusForbidden,
				p.BlockMessage)

			// Close original response body
			if resp.Body != nil {
				resp.Body.Close()
			}

			return blockedResp
		}
	}

	return resp
}
