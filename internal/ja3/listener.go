package ja3

import (
	"bytes"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"

	"ads-httpproxy/pkg/logging"

	"go.uber.org/zap"
)

// SniffedConn wraps a connection and provides access to the sniffed ClientHello
type SniffedConn struct {
	net.Conn
	JA3       string
	JA3Hash   string
	JA4       string // Built authentic implementation
	UserAgent string // populated later by proxy potentially
}

// Listener wraps a net.Listener to sniff TLS Fingerprints
type Listener struct {
	net.Listener
}

func NewListener(l net.Listener) *Listener {
	return &Listener{Listener: l}
}

func (l *Listener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	buf := make([]byte, 16384) // 16KB should be enough for ClientHello
	n, err := c.Read(buf)
	if err != nil && err != io.EOF {
		c.Close()
		return nil, err
	}

	data := buf[:n]
	ja3Str, ja3Hash, ja4Str := parseClientHello(data)
	
	if ja4Str != "" {
		logging.Logger.Debug("TLS Fingerprints Extracted", zap.String("ja4", ja4Str), zap.String("ja3", ja3Hash), zap.String("remote", c.RemoteAddr().String()))
	}

	sc := &SniffedConn{
		Conn:    &prefixedConn{Conn: c, prefix: data},
		JA3:     ja3Str,
		JA3Hash: ja3Hash,
		JA4:     ja4Str,
	}
	return sc, nil
}

type prefixedConn struct {
	net.Conn
	prefix []byte
	reader io.Reader
}

func (c *prefixedConn) Read(b []byte) (n int, err error) {
	if c.reader == nil {
		c.reader = io.MultiReader(bytes.NewReader(c.prefix), c.Conn)
	}
	return c.reader.Read(b)
}

func parseClientHello(data []byte) (string, string, string) {
	// 5 byte Record
	if len(data) < 5 || data[0] != 0x16 {
		return "", "", ""
	}
	
	// MsgType
	if len(data) < 9 || data[5] != 0x01 {
		return "", "", ""
	}

	p := 9
	// ClientVersion
	if p+2 > len(data) { return "", "", "" }
	p += 2

	// Random
	p += 32

	// Session ID
	if p+1 > len(data) { return "", "", "" }
	sessIDLen := int(data[p])
	p += 1 + sessIDLen

	// Cipher Suites
	if p+2 > len(data) { return "", "", "" }
	ciphersLen := int(data[p])<<8 | int(data[p+1])
	p += 2
	
	var ciphers []string
	var rawCiphers []uint16
	for i := 0; i < ciphersLen; i += 2 {
		if p+i+2 > len(data) { break }
		val := uint16(data[p+i])<<8 | uint16(data[p+i+1])
		// Ignore GREASE: low byte nibble == 0xa and high byte nibble == 0xa
		if (val & 0x0f0f) == 0x0a0a { continue }
		rawCiphers = append(rawCiphers, val)
		ciphers = append(ciphers, fmt.Sprintf("%04x", val))
	}
	p += ciphersLen

	// Compression
	if p+1 > len(data) { return "", "", "" }
	compLen := int(data[p])
	p += 1 + compLen

	// Extensions
	var exts []string
	var rawExts []uint16
	
	sniVal := "i"
	alpnVal := "00"
	tlsVer := "12" // default if not found
	
	if p+2 <= len(data) {
		extsLen := int(data[p])<<8 | int(data[p+1])
		p += 2
		end := p + extsLen
		
		for p+4 <= end && p+4 <= len(data) {
			extType := uint16(data[p])<<8 | uint16(data[p+1])
			extLen := int(data[p+2])<<8 | int(data[p+3])
			p += 4
			
			if (extType & 0x0f0f) == 0x0a0a {
				p += extLen
				continue
			}
			
			rawExts = append(rawExts, extType)
			exts = append(exts, fmt.Sprintf("%d", extType))
			
			// SNI
			if extType == 0x0000 && extLen > 0 {
				sniVal = "d"
			}
			// ALPN
			if extType == 0x0010 && extLen > 2 {
				// Read first ALPN protocol
				if p+3 <= end && p+3 <= len(data) {
					alpnStrLen := int(data[p+2])
					if p+3+alpnStrLen <= end && p+3+alpnStrLen <= len(data) && alpnStrLen >= 2 {
						alpnBytes := data[p+3:p+3+2]
						alpnVal = ""
						for _, charByte := range alpnBytes {
							if (charByte >= 'a' && charByte <= 'z') || (charByte >= '0' && charByte <= '9') {
								alpnVal += string(charByte)
							}
						}
						if len(alpnVal) < 2 {
							alpnVal = string(alpnBytes[0]) + string(alpnBytes[1])
						}
					}
				}
			}
			
			// Supported Versions
			if extType == 0x002b && extLen > 1 {
				 if p+1 <= len(data) {
					 vlen := int(data[p])
					 for j := 0; j < vlen; j += 2 {
						 if p+1+j+2 <= len(data) {
							 v := uint16(data[p+1+j])<<8 | uint16(data[p+1+j+1])
							 if v == 0x7f13 { tlsVer = "13" } // TLS 1.3
						 }
					 }
				 }
			}
			
			p += extLen
		}
	}
	
	// Sorting for JA4
	sort.Slice(rawCiphers, func(i, j int) bool { return rawCiphers[i] < rawCiphers[j] })
	sort.Slice(rawExts, func(i, j int) bool { return rawExts[i] < rawExts[j] })
	
	// Create Hash B (Ciphers)
	var cipherParts []string
	for _, c := range rawCiphers { cipherParts = append(cipherParts, fmt.Sprintf("%04x", c)) }
	hashBFull := sha256.Sum256([]byte(strings.Join(cipherParts, ",")))
	hashB := fmt.Sprintf("%x", hashBFull)[:12]
	if len(rawCiphers) == 0 { hashB = "000000000000" }
	
	// Create Hash C (Extensions)
	var extParts []string
	for _, e := range rawExts { extParts = append(extParts, fmt.Sprintf("%04x", e)) }
	hashCFull := sha256.Sum256([]byte(strings.Join(extParts, ",")))
	hashC := fmt.Sprintf("%x", hashCFull)[:12]
	if len(rawExts) == 0 { hashC = "000000000000" }
	
	formatExts := len(rawExts)
	formatCiphers := len(rawCiphers)
	
	// Part A
	if len(alpnVal) < 2 { alpnVal = "00" }
	if len(alpnVal) > 2 { alpnVal = alpnVal[:2] }
	partA := fmt.Sprintf("t%s%s%02d%02d%s", tlsVer, sniVal, formatCiphers, formatExts, alpnVal)
	ja4 := fmt.Sprintf("%s_%s_%s", partA, hashB, hashC)

	// Simulate old JA3 string formats
	ja3Str := fmt.Sprintf("771,%s,%s,,", strings.Join(ciphers, "-"), strings.Join(exts, "-"))
	hash := md5.Sum([]byte(ja3Str))
	ja3Hash := hex.EncodeToString(hash[:])
	
	return ja3Str, ja3Hash, ja4
}
