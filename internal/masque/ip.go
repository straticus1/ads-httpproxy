package masque

import (
	"context"
	"net/http"
	"time"

	"ads-httpproxy/pkg/logging"
	"go.uber.org/zap"
)

// HandleIP processes RFC 9484 CONNECT-IP requests
// Handles arbitrary IP packets routed through the tunnel. 
// Uses Capsule Protocol similar to UDP but IP payloads.
func HandleIP(w http.ResponseWriter, r *http.Request) {
	if r.Method != "CONNECT-IP" {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Capsule-Protocol", "?1")
	w.WriteHeader(http.StatusSwitchingProtocols)

	hj, ok := w.(http.Hijacker)
	if !ok {
		logging.Logger.Error("Webserver doesn't support hijacking")
		return
	}
	
	conn, _, err := hj.Hijack()
	if err != nil {
		logging.Logger.Error("Hijack error", zap.Error(err))
		return
	}
	defer conn.Close()

	// For IP Proxying, we mock the IP packet ingestion since we don't have a local TUN/TAP 
    // configured natively. We just read capsules and discard/bounce contextually for the proxy demo.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		for {
			_, err := ReadCapsule(conn)
			if err != nil {
				cancel()
				return
			}
			// In fully implemented reverse proxy routing mode, we'd write to a raw socket or TUN device
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
			// keepalive loop or route returned packets from TUN device back via WriteCapsule
		}
	}
}
