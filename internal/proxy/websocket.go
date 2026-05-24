package proxy

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"

	"ads-httpproxy/pkg/logging"
	"go.uber.org/zap"
)

// HandleWebSocket intercepts a websocket Upgrade request and manually proxies
// the TCP streams, bypassing the heavyweight HTTP round-trippers.
func HandleWebSocket(w http.ResponseWriter, r *http.Request, target *url.URL) {
	logging.Logger.Info("Upgrading connection to WebSocket", zap.String("target", target.String()))

	targetAddr := target.Host
	if !strings.Contains(targetAddr, ":") {
		if target.Scheme == "https" || target.Scheme == "wss" {
			targetAddr += ":443"
		} else {
			targetAddr += ":80"
		}
	}

	// Dial Upstream
	var upConn net.Conn
	var err error
	if target.Scheme == "https" || target.Scheme == "wss" {
		upConn, err = tls.Dial("tcp", targetAddr, &tls.Config{InsecureSkipVerify: true}) // Trust custom domains internally
	} else {
		upConn, err = net.Dial("tcp", targetAddr)
	}

	if err != nil {
		logging.Logger.Error("Failed to dial WebSocket upstream", zap.Error(err))
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer upConn.Close()

	// Perform HTTP handshake forwarding (Write original request to upstream)
	err = r.Write(upConn)
	if err != nil {
		logging.Logger.Error("Failed to write WebSocket handshake to upstream", zap.Error(err))
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}

	// Hijack the client connection
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		logging.Logger.Error("ResponseWriter does not support hijacking")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		logging.Logger.Error("Failed to hijack client connection for WebSocket", zap.Error(err))
		return
	}
	defer clientConn.Close()

	// Bidirectional Copy Streams
	errc := make(chan error, 2)
	go func() {
		_, err := io.Copy(clientConn, upConn)
		errc <- err
	}()
	go func() {
		_, err := io.Copy(upConn, clientConn)
		errc <- err
	}()

	<-errc // Wait for first connection drop
}
