package auth

import (
	"net/http"
	"sync"
	"time"

	"ads-httpproxy/internal/config"

	"go.uber.org/zap"
)

// Authenticator defines the interface for authentication mechanisms
type Authenticator interface {
	// Challenge returns the WWW-Authenticate/Proxy-Authenticate header value
	// and an error if the challenge generation fails.
	Challenge(req *http.Request) (string, error)

	// Authenticate validates the request. It returns true if authenticated,
	// the authenticated user (if any), and an error if something goes wrong.
	// It may also return a new challenge header if the handshake is ongoing.
	Authenticate(req *http.Request) (bool, string, string, error)
}

// SessionManager handles stateful authentication flows (like NTLM)
type SessionManager struct {
	sessions map[string]*Session
	mu       sync.RWMutex
}

type Session struct {
	State     interface{}
	CreatedAt time.Time
}

func NewSessionManager() *SessionManager {
	sm := &SessionManager{
		sessions: make(map[string]*Session),
	}
	go sm.StartCleanup()
	return sm
}

// StartCleanup periodically removes expired sessions
func (sm *SessionManager) StartCleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		sm.mu.Lock()
		now := time.Now()
		for k, v := range sm.sessions {
			if now.Sub(v.CreatedAt) > 1*time.Hour { // 1 Hour Session Timeout
				delete(sm.sessions, k)
			}
		}
		sm.mu.Unlock()
	}
}

func (sm *SessionManager) Get(key string) *Session {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.sessions[key]
}

func (sm *SessionManager) Set(key string, state interface{}) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.sessions[key] = &Session{
		State:     state,
		CreatedAt: time.Now(),
	}
}

func (sm *SessionManager) Delete(key string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	delete(sm.sessions, key)
}

// Factory returns the appropriate Authenticator based on config
func NewAuthenticator(cfg *config.AuthConfig, logger *zap.Logger) (Authenticator, error) {
	switch cfg.Mechanism {
	case "ldap":
		return NewLDAPAuthenticator(cfg.LDAP, logger)
	case "ad":
		return NewActiveDirectoryAuthenticator(cfg.LDAP, logger)
	case "ntlm":
		return NewNTLMAuthenticator(cfg, logger), nil
	case "kerberos":
		return NewKerberosAuthenticator(cfg, logger)
	case "oidc":
		return NewOIDCAuthenticator(cfg.OIDC, logger)
	case "oauth2":
		return NewOAuth2Authenticator(cfg.OAuth2, logger)
	case "saml":
		return NewSAMLAuthenticator(cfg.SAML, logger)
	default:
		return nil, nil // No auth
	}
}
