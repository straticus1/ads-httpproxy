package proxy

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
)

// UDPRelay forwards opaque datagrams to one fixed upstream, including QUIC
// protocols other than HTTP/3. Each client gets a separate upstream UDP socket.
type UDPRelay struct {
	listener *net.UDPConn
	target   *net.UDPAddr
	capacity int
	idle     time.Duration
	mu       sync.Mutex
	sessions map[string]*udpSession
	closed   bool
	wg       sync.WaitGroup
}
type udpSession struct {
	conn   *net.UDPConn
	client *net.UDPAddr
	last   time.Time
}

func NewUDPRelay(addr, target string, capacity int, idle time.Duration) (*UDPRelay, error) {
	if capacity <= 0 {
		capacity = 256
	}
	if idle <= 0 {
		idle = time.Minute
	}
	targetAddr, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		return nil, fmt.Errorf("QUIC relay target: %w", err)
	}
	local, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	listener, err := net.ListenUDP("udp", local)
	if err != nil {
		return nil, err
	}
	return &UDPRelay{listener: listener, target: targetAddr, capacity: capacity, idle: idle, sessions: map[string]*udpSession{}}, nil
}
func (r *UDPRelay) Addr() net.Addr { return r.listener.LocalAddr() }
func (r *UDPRelay) Serve(ctx context.Context) error {
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			r.Close()
		case <-done:
		}
	}()
	defer close(done)
	defer r.Close()
	buffer := make([]byte, 65535)
	for {
		n, client, err := r.listener.ReadFromUDP(buffer)
		if err != nil {
			r.mu.Lock()
			closed := r.closed
			r.mu.Unlock()
			if closed {
				return nil
			}
			return err
		}
		session, err := r.session(client)
		if err != nil {
			continue
		}
		if _, err := session.conn.Write(buffer[:n]); err != nil {
			r.remove(client.String(), session)
		}
	}
}
func (r *UDPRelay) session(client *net.UDPAddr) (*udpSession, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil, net.ErrClosed
	}
	key := client.String()
	if existing := r.sessions[key]; existing != nil {
		existing.last = time.Now()
		return existing, nil
	}
	// Expire idle clients before enforcing the bound; never evict an active one.
	now := time.Now()
	for key, s := range r.sessions {
		if now.Sub(s.last) >= r.idle {
			s.conn.Close()
			delete(r.sessions, key)
		}
	}
	if len(r.sessions) >= r.capacity {
		return nil, fmt.Errorf("QUIC relay client capacity reached")
	}
	conn, err := net.DialUDP("udp", nil, r.target)
	if err != nil {
		return nil, err
	}
	session := &udpSession{conn: conn, client: client, last: now}
	r.sessions[key] = session
	r.wg.Add(1)
	go r.readReplies(key, session)
	return session, nil
}
func (r *UDPRelay) readReplies(key string, s *udpSession) {
	defer r.wg.Done()
	defer r.remove(key, s)
	buffer := make([]byte, 65535)
	for {
		r.mu.Lock()
		last := s.last
		r.mu.Unlock()
		s.conn.SetReadDeadline(last.Add(r.idle))
		n, err := s.conn.Read(buffer)
		if err != nil {
			if e, ok := err.(net.Error); ok && e.Timeout() {
				r.mu.Lock()
				active := time.Since(s.last) < r.idle
				r.mu.Unlock()
				if active {
					continue
				}
			}
			return
		}
		r.mu.Lock()
		s.last = time.Now()
		r.mu.Unlock()
		if _, err := r.listener.WriteToUDP(buffer[:n], s.client); err != nil {
			return
		}
	}
}
func (r *UDPRelay) remove(key string, s *udpSession) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.sessions[key] == s {
		delete(r.sessions, key)
	}
	s.conn.Close()
}
func (r *UDPRelay) Close() error {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil
	}
	r.closed = true
	err := r.listener.Close()
	for _, s := range r.sessions {
		s.conn.Close()
	}
	r.sessions = map[string]*udpSession{}
	r.mu.Unlock()
	r.wg.Wait()
	return err
}
