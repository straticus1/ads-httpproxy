package visibility

import (
	"net"
)

// TrackedListener wraps a net.Listener to track active connections.
type TrackedListener struct {
	net.Listener
}

func NewTrackedListener(l net.Listener) *TrackedListener {
	return &TrackedListener{Listener: l}
}

func (l *TrackedListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	id := RegisterConnection(c)
	return &trackedConn{Conn: c, id: id}, nil
}

type trackedConn struct {
	net.Conn
	id string
}

func (c *trackedConn) Close() error {
	UnregisterConnection(c.id)
	return c.Conn.Close()
}
