package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"time"
)

const (
	HeaderSignature = "X-Proxy-Signature"
	HeaderTimestamp = "X-Proxy-Timestamp"
)

func AuthMiddleware(secret string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ts := r.Header.Get(HeaderTimestamp)
			sig := r.Header.Get(HeaderSignature)

			if ts == "" || sig == "" {
				http.Error(w, "Missing authentication headers", http.StatusUnauthorized)
				return
			}

			// Verify timestamp freshness (e.g. within 5 minutes)
			parsedTs, err := time.Parse(time.RFC3339, ts)
			if err != nil || time.Since(parsedTs) > 5*time.Minute || time.Since(parsedTs) < -5*time.Minute {
				http.Error(w, "Invalid timestamp", http.StatusUnauthorized)
				return
			}

			// Verify signature: HMAC-SHA256(secret, method + path + timestamp)
			payload := r.Method + r.URL.Path + ts
			expectedSig := computeSignature(secret, payload)

			if !hmac.Equal([]byte(sig), []byte(expectedSig)) {
				http.Error(w, "Invalid signature", http.StatusUnauthorized)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func computeSignature(secret, payload string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}

// ComputeSignature exported for CLI usage
func ComputeSignature(secret, payload string) string {
	return computeSignature(secret, payload)
}
