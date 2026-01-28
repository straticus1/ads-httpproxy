package protocol

import (
	"io"
	"net"

	"ads-httpproxy/pkg/logging"

	"go.uber.org/zap"
)

type Listener struct {
	net.Listener
	sniffer   *Sniffer
	safeguard *Safeguard
}

func NewListener(l net.Listener) *Listener {
	return &Listener{
		Listener:  l,
		sniffer:   NewSniffer(),
		safeguard: NewSafeguard(),
	}
}

func (l *Listener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	// Sniff first bytes
	buf := make([]byte, 50) // Enough for SSH banner or HTTP method or TLS header
	n, err := c.Read(buf)
	if err != nil && err != io.EOF {
		c.Close()
		return nil, err
	}

	data := buf[:n]
	proto := l.sniffer.Detect(data)

	// Check Safeguard
	if !l.safeguard.Check(proto, c.RemoteAddr().String()) {
		c.Close()
		// Return a distinct error or just block?
		// If we just loop Accept(), we hide the connection from the server loop.
		// NOTE: In a robust implementation, we should loop here to drop silently and wait for next conn.
		// For now, we return a closed connection or error?
		// If we return error, the server loop might log it or exit.
		// Better to Close and recurse Accept() to "drop" it.
		return l.Accept()
	}

	logging.Logger.Debug("Protocol Detected", zap.String("protocol", string(proto)), zap.String("remote", c.RemoteAddr().String()))

	return &SniffedConn{
		Conn:     c,
		Protocol: proto,
		prefix:   data,
	}, nil
}
