package plugin

import (
	"encoding/json"
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

// APIVersion identifies the hook contract supported by the proxy.
const APIVersion = "1"

// Versioned is optional; legacy plugins without it use API version 1.
type Versioned interface {
	APIVersion() string
	Version() string
}

// Configurable receives an isolated JSON configuration before registration.
// Configure must return an error if the settings cannot be applied.
type Configurable interface{ Configure(json.RawMessage) error }
