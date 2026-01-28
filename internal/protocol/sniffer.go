package protocol

import (
	"bytes"
	"io"
	"net"
)

type Protocol string

const (
	ProtocolUnknown Protocol = "unknown"
	ProtocolHTTP    Protocol = "http"
	ProtocolTLS     Protocol = "tls"
	ProtocolSSH     Protocol = "ssh"
	ProtocolTelnet  Protocol = "telnet"
)

// Sniffer peeks at the connection to determine the protocol
type Sniffer struct{}

func NewSniffer() *Sniffer {
	return &Sniffer{}
}

// Detect identifies the protocol from the prefix bytes
func (s *Sniffer) Detect(prefix []byte) Protocol {
	if len(prefix) < 3 {
		return ProtocolUnknown
	}

	// SSH: "SSH-"
	if len(prefix) >= 4 && string(prefix[:4]) == "SSH-" {
		return ProtocolSSH
	}

	// Telnet: FF FD (IAC DO) or FF FB (IAC WILL)
	if prefix[0] == 0xFF && (prefix[1] == 0xFD || prefix[1] == 0xFB) {
		return ProtocolTelnet
	}

	// TLS: 16 03 (Handshake, Version 3.x)
	if prefix[0] == 0x16 && prefix[1] == 0x03 {
		return ProtocolTLS
	}

	// HTTP: GET, POST, HEAD, PUT, DELETE, CONNECT, OPTIONS, TRACE, PATCH
	methods := []string{"GET ", "POST ", "HEAD ", "PUT ", "CONNECT ", "OPTIONS "}
	for _, m := range methods {
		if len(prefix) >= len(m) && string(prefix[:len(m)]) == m {
			return ProtocolHTTP
		}
	}

	return ProtocolUnknown
}

// SniffedConn wraps a connection and provides the sniffed protocol
type SniffedConn struct {
	net.Conn
	Protocol Protocol
	prefix   []byte
	reader   io.Reader
}

func (c *SniffedConn) Read(b []byte) (n int, err error) {
	if c.reader == nil {
		c.reader = io.MultiReader(bytes.NewReader(c.prefix), c.Conn)
	}
	return c.reader.Read(b)
}
