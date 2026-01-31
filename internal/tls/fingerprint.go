package tls

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"sort"
	"strings"
)

// Fingerprint represents a client TLS/HTTP fingerprint
type Fingerprint struct {
	JA3       string
	UserAgent string
	Headers   []string // Order of headers
}

// GetFingerprint extracts a basic fingerprint from a request.
// Note: True JA3 requires access to the raw ClientHello which is hidden by net/http.
// In a full MITM scenario, we would extract this from the hijacked connection.
// For now, we simulate "Advanced Filtering" capabilities via Header Ordering + UA.
func GetFingerprint(req *http.Request) *Fingerprint {
	fp := &Fingerprint{
		UserAgent: req.UserAgent(),
		Headers:   make([]string, 0, len(req.Header)),
	}

	// Capture Header Order (approximate, Go map randomization makes this hard without raw parsing)
	// We sort to have a deterministic "Set" signature at least.
	for k := range req.Header {
		fp.Headers = append(fp.Headers, k)
	}
	sort.Strings(fp.Headers)

	fp.JA3 = calculatePseudoJA3(fp)

	return fp
}

func calculatePseudoJA3(fp *Fingerprint) string {
	// Creating a hash based on available signals
	raw := fp.UserAgent + "|" + strings.Join(fp.Headers, ",")
	hash := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(hash[:])
}

// IsBot returns true if the fingerprint matches known bot patterns
func (fp *Fingerprint) IsBot() bool {
	ua := strings.ToLower(fp.UserAgent)
	if strings.Contains(ua, "curl") || strings.Contains(ua, "python") || strings.Contains(ua, "bot") {
		return true
	}
	return false
}
