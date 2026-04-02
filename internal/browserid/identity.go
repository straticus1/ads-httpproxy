package browserid

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"ads-httpproxy/internal/ja3"
)

type Identity struct {
	ID        string `json:"id"`
	IP        string `json:"ip"`
	Score     int    `json:"score"` 
	Timestamp int64  `json:"ts"`
}

var secretKey = []byte("super-secret-edge-key-generated-at-startup-ads") // In prod this should be in config

func SetSecret(secret string) {
	if secret != "" {
		secretKey = []byte(secret)
	}
}

// Generate creates a signed Token string based on ja4/ja3 and ip
func Generate(req *http.Request) (string, *Identity) {
	ip, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil || ip == "" {
		ip = req.RemoteAddr
	}

	var tlsHash string
	if sniffed, ok := req.Context().Value("ja3_conn").(*ja3.SniffedConn); ok {
		if sniffed.JA4 != "" {
			tlsHash = sniffed.JA4
		} else {
			tlsHash = sniffed.JA3Hash
		}
	}

	rawID := fmt.Sprintf("%s|%s|%s", ip, tlsHash, req.UserAgent())
	hash := sha256.Sum256([]byte(rawID))
	idStr := fmt.Sprintf("%x", hash)

	ident := &Identity{
		ID:        idStr,
		IP:        ip,
		Score:     0,
		Timestamp: time.Now().Unix(),
	}

	data, _ := json.Marshal(ident)
	b64Data := base64.RawURLEncoding.EncodeToString(data)
	
	mac := hmac.New(sha256.New, secretKey)
	mac.Write([]byte(b64Data))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return fmt.Sprintf("%s.%s", b64Data, sig), ident
}

func Verify(token string) (*Identity, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid token format")
	}

	mac := hmac.New(sha256.New, secretKey)
	mac.Write([]byte(parts[0]))
	expectedSig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(parts[1]), []byte(expectedSig)) {
		return nil, fmt.Errorf("invalid signature")
	}

	data, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, err
	}

	var ident Identity
	if err := json.Unmarshal(data, &ident); err != nil {
		return nil, err
	}

	// Verify expiration (e.g. 24h)
	if time.Now().Unix()-ident.Timestamp > 86400 {
		return nil, fmt.Errorf("token expired")
	}

	return &ident, nil
}
