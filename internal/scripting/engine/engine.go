package engine

import (
	"context"
	"net/http"
)

// Engine defines the interface for a scripting backend.
type Engine interface {
	// Name returns the engine name (e.g., "tengo").
	Name() string

	// OnRequest is called before the request is sent to the backend.
	// It can modify the request or return an error to block it.
	OnRequest(ctx context.Context, req *http.Request) error

	// OnResponse is called after the response is received from the backend.
	// It can modify the response.
	OnResponse(ctx context.Context, resp *http.Response) error
}
