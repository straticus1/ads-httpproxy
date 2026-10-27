package proxy

import (
	"context"
	"net/http"

	"ads-httpproxy/internal/auth"
	"ads-httpproxy/internal/headerpolicy"
)

type headerContextKey struct{}
type headerContext struct {
	snapshot          headerpolicy.Snapshot
	request, response []headerpolicy.Operations
	captured          bool
}
type responseHeaderKey struct{}
type responseHeaderCapture struct {
	via          []string
	major, minor int
}

func (s *Server) prepareHeaders(req *http.Request, gateway bool) {
	if s.headerPolicy == nil {
		return
	}
	old, _ := req.Context().Value(headerContextKey{}).(headerContext)
	if old.captured {
		return
	}
	old.snapshot = s.headerPolicy.Capture(req, gateway)
	old.captured = true
	*req = *req.WithContext(context.WithValue(req.Context(), headerContextKey{}, old))
}

func addHeaderActions(req *http.Request, request, response headerpolicy.Operations) {
	state, _ := req.Context().Value(headerContextKey{}).(headerContext)
	state.request = append(append([]headerpolicy.Operations(nil), state.request...), request)
	state.response = append(append([]headerpolicy.Operations(nil), state.response...), response)
	*req = *req.WithContext(context.WithValue(req.Context(), headerContextKey{}, state))
}

func (s *Server) applyRequestHeaders(req *http.Request) error {
	s.prepareHeaders(req, false)
	state := req.Context().Value(headerContextKey{}).(headerContext)
	identity := ""
	if p, ok := auth.PrincipalFromContext(req.Context()); ok && (p.Subject != "anonymous" || p.Issuer != "local") {
		identity = p.Username
		if identity == "" {
			identity = p.Subject
		}
	}
	return s.headerPolicy.ApplyRequest(req, &state.snapshot, identity, nil, state.request...)
}

// Runs after request hooks, before cache lookup and network serialization.
type headerRequestTransport struct {
	s    *Server
	next http.RoundTripper
}

func (t *headerRequestTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := t.s.applyRequestHeaders(req); err != nil {
		return nil, err
	}
	resp, err := t.next.RoundTrip(req)
	if resp != nil {
		if capture, ok := req.Context().Value(responseHeaderKey{}).(*responseHeaderCapture); ok {
			capture.via = append([]string(nil), resp.Header.Values("Via")...)
			capture.major, capture.minor = resp.ProtoMajor, resp.ProtoMinor
		}
	}
	return resp, err
}

// Each transport invocation owns its response capture, including cache hits.
type headerResponseTransport struct {
	s    *Server
	next http.RoundTripper
}

func (t *headerResponseTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	t.s.prepareHeaders(req, false)
	capture := &responseHeaderCapture{}
	req = req.WithContext(context.WithValue(req.Context(), responseHeaderKey{}, capture))
	resp, err := t.next.RoundTrip(req)
	if err != nil || resp == nil {
		return resp, err
	}
	// Preserve our private capture even when a cache or plugin returns another request.
	resp.Request = req
	return resp, nil
}

// Finalize after response middleware, including ICAP and plugins.
func (s *Server) finalizeResponseHeaders(resp *http.Response) error {
	if s.headerPolicy == nil || resp == nil || resp.Request == nil {
		return nil
	}
	req := resp.Request
	state, ok := req.Context().Value(headerContextKey{}).(headerContext)
	if !ok || !state.captured {
		return nil
	}
	capture, _ := req.Context().Value(responseHeaderKey{}).(*responseHeaderCapture)
	// Locally generated authentication/error responses retain their challenges.
	if capture == nil {
		return nil
	}
	var via []string
	if capture != nil {
		via = capture.via
		if capture.major != 0 {
			resp.ProtoMajor, resp.ProtoMinor = capture.major, capture.minor
		}
	}
	resp.Header = resp.Header.Clone()
	return s.headerPolicy.ApplyResponse(resp, &state.snapshot, via, state.response...)
}

// Adaptation services can replace message contents, but cannot replace the
// authenticated context, ingress metadata, cancellation, or TLS peer identity.
func preserveRequestTrust(updated, original *http.Request) *http.Request {
	updated = updated.WithContext(original.Context())
	updated.RemoteAddr = original.RemoteAddr
	updated.TLS = original.TLS
	return updated
}
