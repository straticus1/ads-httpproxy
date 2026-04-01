package pac

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"

	"ads-httpproxy/pkg/logging"

	"go.uber.org/zap"
)

// Handler serves PAC files with per-user policies
type Handler struct {
	generator      *Generator
	mu             sync.RWMutex
	policies       map[string]*Policy // userID -> Policy
	tenantPolicies map[string]*Policy // tenantID -> Policy
	defaultPolicy  *Policy
}

// NewHandler creates a new PAC handler
func NewHandler(defaultProxy string) *Handler {
	return &Handler{
		generator:      NewGenerator(defaultProxy),
		policies:       make(map[string]*Policy),
		tenantPolicies: make(map[string]*Policy),
		defaultPolicy: &Policy{
			ProxyAddr: defaultProxy,
			ProxyPort: 8080,
			// Default: no blocking, just route through proxy
		},
	}
}

// SetUserPolicy configures policy for a specific user
func (h *Handler) SetUserPolicy(userID string, policy *Policy) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.policies[userID] = policy
	logging.Logger.Info("Set user policy", zap.String("user", userID))
}

// SetTenantPolicy configures policy for a tenant
func (h *Handler) SetTenantPolicy(tenantID string, policy *Policy) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.tenantPolicies[tenantID] = policy
	logging.Logger.Info("Set tenant policy", zap.String("tenant", tenantID))
}

// ServeHTTP handles PAC file requests
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Extract user/tenant from query params or auth
	userID := r.URL.Query().Get("user")
	tenantID := r.URL.Query().Get("tenant")

	// Try to get from auth header if not in query
	if userID == "" {
		if username, _, ok := r.BasicAuth(); ok {
			userID = username
		}
	}

	// Try custom header
	if userID == "" {
		userID = r.Header.Get("X-User-ID")
	}
	if tenantID == "" {
		tenantID = r.Header.Get("X-Tenant-ID")
	}

	// Get policy
	policy := h.getPolicyForUser(userID, tenantID)

	// Generate PAC file
	pac, err := h.generator.Generate(policy)
	if err != nil {
		logging.Logger.Error("Failed to generate PAC file", zap.Error(err))
		http.Error(w, "Failed to generate PAC file", http.StatusInternalServerError)
		return
	}

	// Serve with correct content type
	w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")

	if userID != "" {
		logging.Logger.Debug("Served PAC file",
			zap.String("user", userID),
			zap.String("tenant", tenantID),
			zap.Int("size", len(pac)))
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(pac))
}

// getPolicyForUser retrieves the effective policy for a user
func (h *Handler) getPolicyForUser(userID, tenantID string) *Policy {
	h.mu.RLock()
	defer h.mu.RUnlock()

	// Check for user-specific policy
	if userID != "" {
		if policy, ok := h.policies[userID]; ok {
			return policy
		}
	}

	// Check for tenant policy
	if tenantID != "" {
		if policy, ok := h.tenantPolicies[tenantID]; ok {
			return policy
		}
	}

	// Return default
	return h.defaultPolicy
}

// HandleAPI provides REST API for policy management
func (h *Handler) HandleAPI(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.handleGetPolicies(w, r)
	case http.MethodPost:
		h.handleSetPolicy(w, r)
	case http.MethodDelete:
		h.handleDeletePolicy(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *Handler) handleGetPolicies(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("user")
	tenantID := r.URL.Query().Get("tenant")

	h.mu.RLock()
	defer h.mu.RUnlock()

	var result interface{}

	if userID != "" {
		// Get specific user policy
		policy, ok := h.policies[userID]
		if !ok {
			http.Error(w, "User not found", http.StatusNotFound)
			return
		}
		result = policy
	} else if tenantID != "" {
		// Get specific tenant policy
		policy, ok := h.tenantPolicies[tenantID]
		if !ok {
			http.Error(w, "Tenant not found", http.StatusNotFound)
			return
		}
		result = policy
	} else {
		// List all policies
		result = map[string]interface{}{
			"users":   h.policies,
			"tenants": h.tenantPolicies,
			"default": h.defaultPolicy,
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func (h *Handler) handleSetPolicy(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserID   string  `json:"user_id"`
		TenantID string  `json:"tenant_id"`
		Policy   *Policy `json:"policy"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if req.Policy == nil {
		http.Error(w, "Policy is required", http.StatusBadRequest)
		return
	}

	if req.UserID != "" {
		h.SetUserPolicy(req.UserID, req.Policy)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{
			"status": "success",
			"user":   req.UserID,
		})
	} else if req.TenantID != "" {
		h.SetTenantPolicy(req.TenantID, req.Policy)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{
			"status": "success",
			"tenant": req.TenantID,
		})
	} else {
		http.Error(w, "Either user_id or tenant_id is required", http.StatusBadRequest)
	}
}

func (h *Handler) handleDeletePolicy(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("user")
	tenantID := r.URL.Query().Get("tenant")

	h.mu.Lock()
	defer h.mu.Unlock()

	if userID != "" {
		delete(h.policies, userID)
		logging.Logger.Info("Deleted user policy", zap.String("user", userID))
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{
			"status": "deleted",
			"user":   userID,
		})
	} else if tenantID != "" {
		delete(h.tenantPolicies, tenantID)
		logging.Logger.Info("Deleted tenant policy", zap.String("tenant", tenantID))
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{
			"status": "deleted",
			"tenant": tenantID,
		})
	} else {
		http.Error(w, "Either user or tenant parameter is required", http.StatusBadRequest)
	}
}

// PresetPolicies provides common policy templates
var PresetPolicies = map[string]*Policy{
	"government": {
		Department:     "Government Agency",
		BlockAdult:     true,
		BlockGambling:  true,
		BlockSocial:    true,
		BlockStreaming: true,
		BlockPiracy:    true,
		BlockCrypto:    true,
		BlockAds:       true,
		BlockWorkHours: true,
		WorkHoursStart: 8,
		WorkHoursEnd:   17,
		RequireAuth:    true,
	},
	"financial": {
		Department:     "Financial Institution",
		BlockAdult:     true,
		BlockGambling:  true,
		BlockSocial:    true, // Often blocked for compliance
		BlockStreaming: true,
		BlockPiracy:    true,
		BlockCrypto:    true, // Prevent mining
		BlockAds:       true,
		BlockWorkHours: true,
		WorkHoursStart: 8,
		WorkHoursEnd:   18,
		RequireAuth:    true,
	},
	"healthcare": {
		Department:     "Healthcare (HIPAA)",
		BlockAdult:     true,
		BlockGambling:  true,
		BlockSocial:    false, // May need for patient engagement
		BlockStreaming: true,
		BlockPiracy:    true,
		BlockCrypto:    true,
		BlockAds:       true,
		BlockWorkHours: true,
		WorkHoursStart: 7,
		WorkHoursEnd:   19,
		RequireAuth:    true,
	},
	"education": {
		Department:     "Educational Institution (CIPA)",
		BlockAdult:     true,
		BlockGambling:  true,
		BlockSocial:    false, // Educational use
		BlockStreaming: false, // Educational videos
		BlockPiracy:    true,
		BlockCrypto:    true,
		BlockAds:       true,
		BlockWorkHours: false,
		RequireAuth:    false,
	},
	"corporate": {
		Department:     "Corporate",
		BlockAdult:     true,
		BlockGambling:  true,
		BlockSocial:    false,
		BlockStreaming: true,
		BlockPiracy:    true,
		BlockCrypto:    true,
		BlockAds:       false,
		BlockWorkHours: true,
		WorkHoursStart: 9,
		WorkHoursEnd:   17,
		RequireAuth:    true,
	},
	"open": {
		Department:     "Open Access",
		BlockAdult:     false,
		BlockGambling:  false,
		BlockSocial:    false,
		BlockStreaming: false,
		BlockPiracy:    false,
		BlockCrypto:    true, // Still block mining
		BlockAds:       false,
		BlockWorkHours: false,
		RequireAuth:    false,
	},
}

// GetPresetPolicy returns a copy of a preset policy
func GetPresetPolicy(name string, proxyAddr string, proxyPort int) *Policy {
	preset, ok := PresetPolicies[name]
	if !ok {
		return nil
	}

	// Copy preset
	policy := *preset
	policy.ProxyAddr = proxyAddr
	policy.ProxyPort = proxyPort

	return &policy
}

// GenerateWPAD creates a WPAD (Web Proxy Auto-Discovery) configuration
func (h *Handler) GenerateWPAD(domain string) string {
	return fmt.Sprintf(`; WPAD configuration for %s
[DEFAULT]
Proxy=http://proxy.%s/proxy.pac
`, domain, domain)
}
