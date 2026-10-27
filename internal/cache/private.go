package cache

import (
	"context"
	"net/http"
)

type privateRequestKey struct{}

// MarkPrivate excludes an authenticated request independently of mutable headers
// or display names. The marker survives cloning and URL/header rewrites.
func MarkPrivate(req *http.Request) {
	*req = *req.WithContext(context.WithValue(req.Context(), privateRequestKey{}, true))
}
