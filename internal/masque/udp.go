package masque

import (
	"context"
	"net"
	"net/http"
	"strings"
	"time"

	"ads-httpproxy/pkg/logging"
	"go.uber.org/zap"
)

// HandleUDP processes RFC 9298 CONNECT-UDP requests
// Typically standard proxies route based on path URI template extraction:
// e.g. path `.../target/port` mapping.
func HandleUDP(w http.ResponseWriter, r *http.Request) {
	if r.Method != "CONNECT-UDP" {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	target := r.Header.Get("Masque-Target")
	if target == "" {
		// Just a fallback fallback parse 
		// URL Format typically looks like: /.well-known/masque/udp/192.0.2.1/443/
		parts := strings.Split(r.URL.Path, "/")
		if len(parts) >= 3 {
			target = parts[len(parts)-2] + ":" + parts[len(parts)-1]
		}
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

	var udpConn net.Conn
	if target != "" && target != ":" {
		udpAddr, err := net.ResolveUDPAddr("udp", target)
		if err == nil {
			udpConn, err = net.DialUDP("udp", nil, udpAddr)
			if err != nil {
				logging.Logger.Error("Failed to dial UDP target", zap.Error(err))
			}
		}
	}

	if udpConn != nil {
		defer udpConn.Close()
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		for {
			c, err := ReadCapsule(conn)
			if err != nil {
				cancel()
				return
			}
			if c.Type == TypeDatagram && udpConn != nil {
				udpConn.Write(c.Value)
			}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return
		default:
			if udpConn != nil {
				buf := make([]byte, 1500)
				udpConn.SetReadDeadline(time.Now().Add(10 * time.Second))
				n, err := udpConn.Read(buf)
				if err == nil {
					WriteCapsule(conn, &Capsule{Type: TypeDatagram, Value: buf[:n]})
				} else if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
					cancel()
					return
				}
			} else {
				time.Sleep(1 * time.Second)
			}
		}
	}
}
