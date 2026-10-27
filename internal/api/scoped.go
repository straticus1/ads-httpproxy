package api

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
)

type tenantScopeKey struct{}

// scopedAuthentication returns true when a known scoped credential was handled,
// including when its privileges are insufficient. It cannot fall back to admin.
func (s *Server) scopedAuthentication(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) bool {
	key := r.Header.Get("X-API-Key")
	if key == "" {
		return false
	}
	digest := sha256.Sum256([]byte(key))
	for _, credential := range s.cfg.APIKeys {
		expected, err := hex.DecodeString(credential.SHA256)
		if err != nil || subtle.ConstantTimeCompare(digest[:], expected) != 1 {
			continue
		}
		needed := ""
		if r.Method == http.MethodGet && r.URL.Path == "/api/analysis/findings" {
			needed = "findings:read"
		}
		if r.Method == http.MethodPost && r.URL.Path == "/api/ai/explain" {
			needed = "ai:explain"
		}
		for _, scope := range credential.Scopes {
			if needed != "" && scope == needed && credential.Tenant != "" {
				next(w, r.WithContext(context.WithValue(r.Context(), tenantScopeKey{}, credential.Tenant)))
				return true
			}
		}
		http.Error(w, "Credential does not authorize this operation", http.StatusForbidden)
		return true
	}
	return false
}

func scopedTenant(w http.ResponseWriter, r *http.Request, requested string) (string, bool) {
	tenant, scoped := r.Context().Value(tenantScopeKey{}).(string)
	if !scoped {
		return requested, true
	}
	if requested != "" && requested != tenant {
		http.Error(w, "Credential does not authorize this tenant", http.StatusForbidden)
		return "", false
	}
	return tenant, true
}
