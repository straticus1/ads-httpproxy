package proxy

import (
	"io"
	"net"
	"sync"
	"time"

	"ads-httpproxy/pkg/logging"

	"go.uber.org/zap"
)

// TCPProxy is a simple TCP forwarder
type TCPProxy struct {
	addr   string
	target string
	stopCh chan struct{}
}

// NewTCPProxy creates a new TCP forwarding proxy
func NewTCPProxy(addr, target string) *TCPProxy {
	return &TCPProxy{
		addr:   addr,
		target: target,
		stopCh: make(chan struct{}),
	}
}

// Serve starts the generic TCP proxy
func (p *TCPProxy) Serve(l net.Listener) error {
	defer l.Close()
	logging.Logger.Info("Starting TCP Proxy", zap.String("addr", p.addr), zap.String("target", p.target))

	for {
		conn, err := l.Accept()
		if err != nil {
			select {
			case <-p.stopCh:
				return nil
			default:
				logging.Logger.Error("TCP Proxy accept error", zap.Error(err))
				continue
			}
		}

		go p.handleConn(conn)
	}
}

func (p *TCPProxy) handleConn(src net.Conn) {
	defer src.Close()

	// Connect to target
	dst, err := net.DialTimeout("tcp", p.target, 10*time.Second)
	if err != nil {
		logging.Logger.Error("Failed to dial target", zap.String("target", p.target), zap.Error(err))
		return
	}
	defer dst.Close()

	logging.Logger.Debug("Proxying TCP connection",
		zap.String("from", src.RemoteAddr().String()),
		zap.String("to", p.target))

	// Bi-directional copy
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(dst, src)
	}()

	go func() {
		defer wg.Done()
		io.Copy(src, dst)
	}()

	wg.Wait()
}
