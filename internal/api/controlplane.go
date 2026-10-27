package api

import (
	"ads-httpproxy/internal/controlplane"
	"encoding/json"
	"io"
	"net/http"
)

func (s *Server) SetControlPlane(m *controlplane.Manager) { s.controlPlane = m }
func (s *Server) handlePolicyBundle(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writePlatform(w, s.controlPlane.Status())
	case http.MethodPut:
		var envelope controlplane.Envelope
		d := json.NewDecoder(http.MaxBytesReader(w, r.Body, controlplane.MaxEnvelopeBytes))
		d.DisallowUnknownFields()
		if d.Decode(&envelope) != nil || d.Decode(new(any)) != io.EOF {
			http.Error(w, "Invalid bundle JSON", 400)
			return
		}
		status, err := s.controlPlane.Apply(envelope)
		if err != nil {
			http.Error(w, err.Error(), 409)
			return
		}
		writePlatform(w, status)
	default:
		http.Error(w, "Method not allowed", 405)
	}
}
