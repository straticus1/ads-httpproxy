package auth

import (
	"encoding/base64"
	"net/http"
	"strings"

	"ads-httpproxy/internal/config"

	"go.uber.org/zap"
)

type NTLMAuthenticator struct {
	logger   *zap.Logger
	sessions *SessionManager
	users    map[string]string
}

func NewNTLMAuthenticator(cfg *config.AuthConfig, logger *zap.Logger) *NTLMAuthenticator {
	return &NTLMAuthenticator{
		logger:   logger,
		sessions: NewSessionManager(),
		users:    cfg.Users,
	}
}

func (a *NTLMAuthenticator) Challenge(req *http.Request) (string, error) {
	return "NTLM", nil
}

func (a *NTLMAuthenticator) Authenticate(req *http.Request) (bool, string, string, error) {
	authHeader := req.Header.Get("Proxy-Authorization")
	if authHeader == "" {
		return false, "", "", nil
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || parts[0] != "NTLM" {
		return false, "", "", nil // Not NTLM or malformed
	}

	blob, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return false, "", "", err
	}

	// Identify message type
	if len(blob) < 12 {
		return false, "", "", nil
	}
	// NTLMSSP
	if string(blob[:8]) != "NTLMSSP\x00" {
		return false, "", "", nil
	}
	// Type 1 = 1, Type 3 = 3
	// Little Endian
	msgType := int(blob[8]) // efficient peek

	key := req.RemoteAddr // Connection tracking

	if msgType == 1 {
		// Type 1: Negotiate
		ctx := NewNTLMServerContext("PROXY") // Target domain/server name
		if err := ctx.ParseType1(blob); err != nil {
			return false, "", "", err
		}

		challenge, err := ctx.GenerateType2()
		if err != nil {
			return false, "", "", err
		}

		// Store context for next step (Type 3)
		a.sessions.Set(key, ctx)

		return false, "", "NTLM " + base64.StdEncoding.EncodeToString(challenge), nil
	} else if msgType == 3 {
		// Type 3: Authenticate
		session := a.sessions.Get(key)
		if session == nil {
			return false, "", "", nil // Session expired or missing (restart handshake)
		}

		ctx, ok := session.State.(*NTLMServerContext)
		if !ok {
			return false, "", "", nil
		}

		user, err := ctx.VerifyType3(blob, a.users)
		if err != nil {
			a.logger.Warn("NTLM authentication failed", zap.String("remote_addr", key), zap.Error(err))
			a.sessions.Delete(key)
			return false, "", "", err
		}

		// Success
		a.sessions.Delete(key)
		return true, user, "", nil
	}

	return false, "", "", nil
}
