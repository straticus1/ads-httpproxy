package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"sync"
	"time"
)

const sessionCookie = "ads_identity_session"

// Browser sessions are opaque, bounded and revocable, and never contain tokens.
// They are instance-local; multi-instance deployments require sticky routing.
type browserSessions struct {
	mu       sync.Mutex
	entries  map[[32]byte]Principal
	capacity int
	ttl      time.Duration
	root     *url.URL
}

func newBrowserSessions(root *url.URL, capacity int, ttl time.Duration) *browserSessions {
	return &browserSessions{entries: make(map[[32]byte]Principal), capacity: capacity, ttl: ttl, root: root}
}

func randomSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func (s *browserSessions) create(w http.ResponseWriter, r *http.Request, p Principal) error {
	id, err := randomSecret()
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for key, entry := range s.entries {
		if !now.Before(entry.ExpiresAt) {
			delete(s.entries, key)
		}
	}
	if len(s.entries) >= s.capacity {
		return errors.New("identity session capacity reached")
	}
	if p.Subject == "" {
		return errors.New("identity has no stable subject")
	}
	if p.ExpiresAt.IsZero() || now.Add(s.ttl).Before(p.ExpiresAt) {
		p.ExpiresAt = now.Add(s.ttl)
	}
	if !now.Before(p.ExpiresAt) {
		return errors.New("identity is expired")
	}
	// Rotate an existing browser session when a new login succeeds.
	if old, err := r.Cookie(sessionCookie); err == nil {
		delete(s.entries, sha256.Sum256([]byte(old.Value)))
	}
	s.entries[sha256.Sum256([]byte(id))] = clonePrincipal(p)
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: id, Path: "/", Secure: s.root.Scheme == "https", HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: int(time.Until(p.ExpiresAt).Seconds()), Expires: p.ExpiresAt})
	return nil
}

func (s *browserSessions) get(r *http.Request) (Principal, bool) {
	if !browserHost(r, s.root) {
		return Principal{}, false
	}
	cookie, err := r.Cookie(sessionCookie)
	if err != nil {
		return Principal{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := sha256.Sum256([]byte(cookie.Value))
	p, ok := s.entries[key]
	if !ok || !time.Now().Before(p.ExpiresAt) {
		delete(s.entries, key)
		return Principal{}, false
	}
	return clonePrincipal(p), true
}

func (s *browserSessions) delete(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if cookie, err := r.Cookie(sessionCookie); err == nil {
		delete(s.entries, sha256.Sum256([]byte(cookie.Value)))
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Path: "/", Secure: s.root.Scheme == "https", HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: -1, Expires: time.Unix(1, 0)})
}

// RevokeSubject invalidates all local sessions for a verified stable subject.
func (s *browserSessions) RevokeSubject(subject string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for key, p := range s.entries {
		if p.Subject == subject {
			delete(s.entries, key)
			n++
		}
	}
	return n
}

func (s *browserSessions) logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "Method not allowed", 405)
		return
	}
	if r.Header.Get("Origin") != s.root.Scheme+"://"+s.root.Host {
		http.Error(w, "Same-origin logout required", 403)
		return
	}
	s.delete(w, r)
	w.WriteHeader(http.StatusNoContent)
}
