package proxy

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestUDPRelaySeparatesClientsAndCloses(t *testing.T) {
	upstream, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	go func() {
		buffer := make([]byte, 65535)
		for {
			n, addr, err := upstream.ReadFromUDP(buffer)
			if err != nil {
				return
			}
			upstream.WriteToUDP(buffer[:n], addr)
		}
	}()
	relay, err := NewUDPRelay("127.0.0.1:0", upstream.LocalAddr().String(), 2, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- relay.Serve(context.Background()) }()
	defer relay.Close()
	addr := relay.Addr().(*net.UDPAddr)
	clients := make([]*net.UDPConn, 2)
	for i := range clients {
		client, err := net.DialUDP("udp", nil, addr)
		if err != nil {
			t.Fatal(err)
		}
		defer client.Close()
		clients[i] = client
		client.SetDeadline(time.Now().Add(2 * time.Second))
		client.Write([]byte{byte(i), 0, 255})
	}
	for i, client := range clients {
		buffer := make([]byte, 100)
		n, err := client.Read(buffer)
		if err != nil {
			t.Fatal(err)
		}
		if n != 3 || buffer[0] != byte(i) || buffer[2] != 255 {
			t.Fatalf("datagram changed: %v", buffer[:n])
		}
	}
	relay.mu.Lock()
	count := len(relay.sessions)
	relay.mu.Unlock()
	if count != 2 {
		t.Fatalf("sessions: %d", count)
	}
	third := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1}
	if _, err := relay.session(third); err == nil {
		t.Fatal("capacity ignored")
	}
	relay.mu.Lock()
	for _, session := range relay.sessions {
		session.last = time.Now().Add(-2 * time.Second)
	}
	relay.mu.Unlock()
	if _, err := relay.session(third); err != nil {
		t.Fatal("expired sessions not evicted", err)
	}
	if err := relay.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("relay failed to shut down")
	}
	if err := relay.Close(); err != nil {
		t.Fatal("close is not idempotent")
	}
}
