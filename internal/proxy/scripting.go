package proxy

import (
	"fmt"
	"net/http"

	"ads-httpproxy/internal/scripting/engine"
	"github.com/elazarl/goproxy"
)

type scriptTransport struct {
	next   http.RoundTripper
	engine engine.Engine
}

func (t *scriptTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := t.engine.OnRequest(req.Context(), req); err != nil {
		if req.Body != nil {
			req.Body.Close()
		}
		return nil, err
	}
	resp, err := t.next.RoundTrip(req)
	if err != nil {
		return resp, err
	}
	if err := t.engine.OnResponse(req.Context(), resp); err != nil {
		if resp.Body != nil {
			resp.Body.Close()
		}
		return nil, err
	}
	return resp, nil
}

func (s *Server) processGatewayResponse(response *http.Response) error {
	ctx := &goproxy.ProxyCtx{Req: response.Request, Resp: response, Proxy: s.proxy}
	originalRequest := response.Request
	current := response
	for _, middleware := range s.respMiddleware {
		current = middleware(current, ctx)
		if current == nil {
			return fmt.Errorf("gateway response rejected")
		}
		ctx.Resp = current
	}
	if current != response {
		*response = *current
	}
	response.Request = originalRequest
	return s.finalizeResponseHeaders(response)
}
