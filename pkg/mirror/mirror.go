package mirror

import (
	"io"
	"net"
)

// MirrorConn wraps a net.Conn and mirrors Read/Write data to a separate writer.
type MirrorConn struct {
	net.Conn
	Mirror io.Writer // Where to write checks
}

func (c *MirrorConn) Read(b []byte) (n int, err error) {
	n, err = c.Conn.Read(b)
	if n > 0 && c.Mirror != nil {
		// Best effort write to mirror, ignore errors to not affect main stream
		go func(data []byte) {
			_, _ = c.Mirror.Write(data)
		}(append([]byte(nil), b[:n]...)) // Copy data to avoid race
	}
	return
}

func (c *MirrorConn) Write(b []byte) (n int, err error) {
	n, err = c.Conn.Write(b)
	if n > 0 && c.Mirror != nil {
		go func(data []byte) {
			_, _ = c.Mirror.Write(data)
		}(append([]byte(nil), b[:n]...))
	}
	return
}

// Listener wraps a net.Listener and mirrors all accepted connections.
type Listener struct {
	net.Listener
	MirrorFactory func(remoteAddr net.Addr) io.Writer
}

func (l *Listener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	if l.MirrorFactory != nil {
		mw := l.MirrorFactory(c.RemoteAddr())
		if mw != nil {
			return &MirrorConn{
				Conn:   c,
				Mirror: mw,
			}, nil
		}
	}
	return c, nil
}
