package protocol

import (
	"os"
	"strings"

	"ads-httpproxy/pkg/logging"

	"go.uber.org/zap"
)

type Safeguard struct {
	iKnowWhatImDoing bool
	badProtocols     map[string]bool
}

func NewSafeguard() *Safeguard {
	s := &Safeguard{
		iKnowWhatImDoing: os.Getenv("I_KNOW_WHAT_I_AM_DOING") == "true",
		badProtocols:     make(map[string]bool),
	}

	badList := os.Getenv("I_KNOW_PROTOCOL_IS_BAD")
	if badList != "" {
		for _, p := range strings.Split(badList, ",") {
			s.badProtocols[strings.TrimSpace(strings.ToLower(p))] = true
		}
	}
	return s
}

// Check returns true if the connection should be allowed
func (s *Safeguard) Check(proto Protocol, remoteAddr string) bool {
	protoStr := string(proto)
	if s.badProtocols[protoStr] {
		if !s.iKnowWhatImDoing {
			logging.Logger.Warn("Blocked risky protocol by Safeguard",
				zap.String("protocol", protoStr),
				zap.String("remote", remoteAddr),
				zap.String("reason", "I_KNOW_WHAT_I_AM_DOING is not strictly set to true"),
			)
			return false
		}
		logging.Logger.Info("Allowed risky protocol (Safeguard override)",
			zap.String("protocol", protoStr),
			zap.String("remote", remoteAddr),
		)
	}
	return true
}
