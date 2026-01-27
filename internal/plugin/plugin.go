package plugin

import (
	"net/http"
)

// Context provides access to request context and proxy state
type Context struct {
	// Add fields as needed, e.g. Session ID, User Info
}

// Plugin defines the interface for proxy plugins
type Plugin interface {
	// Name returns the unique name of the plugin
	Name() string

	// OnRequest is called before the request is sent to the upstream.
	// Returns parameters:
	// - modified request (if nil, original is used)
	// - response (if not nil, the request is blocked and this response is returned to client)
	OnRequest(req *http.Request, ctx *Context) (*http.Request, *http.Response)

	// OnResponse is called after the response is received from upstream.
	// Returns modified response.
	OnResponse(resp *http.Response, ctx *Context) *http.Response
}
