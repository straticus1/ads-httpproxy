package examples

import (
	"net/http"

	"ads-httpproxy/internal/plugin"
)

// HeaderInjectorPlugin injects custom headers into requests and responses
type HeaderInjectorPlugin struct {
	RequestHeaders  map[string]string
	ResponseHeaders map[string]string
}

func NewHeaderInjectorPlugin(reqHeaders, respHeaders map[string]string) *HeaderInjectorPlugin {
	return &HeaderInjectorPlugin{
		RequestHeaders:  reqHeaders,
		ResponseHeaders: respHeaders,
	}
}

func (p *HeaderInjectorPlugin) Name() string {
	return "header-injector"
}

func (p *HeaderInjectorPlugin) OnRequest(req *http.Request, ctx *plugin.Context) (*http.Request, *http.Response) {
	// Inject custom headers into request
	for key, value := range p.RequestHeaders {
		req.Header.Set(key, value)
	}
	return req, nil
}

func (p *HeaderInjectorPlugin) OnResponse(resp *http.Response, ctx *plugin.Context) *http.Response {
	// Inject custom headers into response
	for key, value := range p.ResponseHeaders {
		resp.Header.Set(key, value)
	}
	return resp
}
