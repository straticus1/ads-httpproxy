package peering

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"net"
	"net/http"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"ads-httpproxy/internal/cache"
	"ads-httpproxy/internal/config" // Import visibility
	"ads-httpproxy/internal/visibility"
	"ads-httpproxy/pkg/logging"

	"go.uber.org/zap"
)

// PeerManager handles distributed caching and parent selection
type PeerManager struct {
	cfg      *config.PeeringConfig
	peers    []string
	mu       sync.RWMutex
	cache    *cache.Manager // Cache for looking up hits
	icpConn  *net.UDPConn
	htcpConn *net.UDPConn
	rrIndex  uint64
	stopChan chan struct{}
	stopOnce sync.Once
}

// NewManager creates a new PeerManager
func NewManager(cfg *config.PeeringConfig) (*PeerManager, error) {
	if cfg == nil || !cfg.Enabled {
		return nil, nil // Not enabled
	}

	pm := &PeerManager{
		cfg:      cfg,
		peers:    cfg.Peers,
		stopChan: make(chan struct{}),
	}
	// ...

	// Sort peers for consistent CARP hashing
	sort.Strings(pm.peers)

	// Start Listeners
	if err := pm.startICPListener(); err != nil {
		logging.Logger.Error("Failed to start ICP listener", zap.Error(err))
	}

	if err := pm.startHTCPListener(); err != nil {
		logging.Logger.Error("Failed to start HTCP listener", zap.Error(err))
	}

	return pm, nil
}

// SetCache configures the cache manager
func (pm *PeerManager) SetCache(c *cache.Manager) {
	pm.mu.Lock()
	pm.cache = c
	pm.mu.Unlock()
}

// SelectParent chooses a parent proxy based on CARP algorithm
func (pm *PeerManager) SelectParent(req *http.Request) string {
	if pm == nil || len(pm.peers) == 0 {
		return ""
	}

	if pm.cfg.Algorithm == "round-robin" {
		idx := atomic.AddUint64(&pm.rrIndex, 1)
		return pm.peers[idx%uint64(len(pm.peers))]
	}

	// CARP (Cache Array Routing Protocol) deterministic hashing
	// Hash(URL + PeerID) -> Select Max

	url := req.URL.String()
	var bestPeer string
	var maxHash uint64

	for _, peer := range pm.peers {
		hash := carpHash(url, peer)
		if hash > maxHash {
			maxHash = hash
			bestPeer = peer
		}
	}

	logging.Logger.Debug("CARP Selected Parent", zap.String("url", url), zap.String("peer", bestPeer))
	if bestPeer != "" {
		visibility.RecordPeeringOp(bestPeer, "carp", "selected")
	}
	return bestPeer
}

// carpHash is a simplified CARP-like hash function
func carpHash(url, peer string) uint64 {
	// Combine and hash
	h := sha256.New()
	h.Write([]byte(url))
	h.Write([]byte(peer))
	sum := h.Sum(nil)

	// Use first 8 bytes as uint64
	var v uint64
	for i := 0; i < 8; i++ {
		v = (v << 8) | uint64(sum[i])
	}
	return v
}

// startICPListener listens for ICP queries (UDP 3130)
func (pm *PeerManager) startICPListener() error {
	addr := fmt.Sprintf(":%d", pm.cfg.ICPPort)
	if addr == ":0" {
		addr = ":3130"
	}

	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return err
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return err
	}
	pm.icpConn = conn

	logging.Logger.Info("ICP Listener started", zap.String("addr", addr))

	go func() {
		buf := make([]byte, 16384)
		for {
			select {
			case <-pm.stopChan:
				return
			default:
				conn.SetReadDeadline(time.Now().Add(1 * time.Second))
				n, peerAddr, err := conn.ReadFromUDP(buf)
				if err != nil {
					if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
						continue
					}
					return
				}

				if n < 20 { // Min header size
					continue
				}

				// Handle ICP Query (RFC 2186)
				opcode := buf[0]
				reqNum := make([]byte, 4)
				copy(reqNum, buf[4:8])

				if opcode == 1 { // ICP_OP_QUERY
					// Payload starts at 20, null terminated URL
					payload := buf[20:n]

					urlLen := bytes.IndexByte(payload, 0)
					if urlLen == -1 {
						urlLen = len(payload)
					}
					urlStr := string(payload[:urlLen])

					// Check Cache
					pm.mu.RLock()
					hit := false
					if pm.cache != nil {
						val, found := pm.cache.Get(urlStr)
						hit = found && len(val) > 0
					}
					pm.mu.RUnlock()

					// Prepare Response
					respOp := byte(3) // ICP_OP_MISS
					if hit {
						respOp = 2 // ICP_OP_HIT
					}

					resp := make([]byte, 20)
					resp[0] = respOp
					resp[1] = 2  // Version 2
					resp[2] = 0  // Length upper
					resp[3] = 20 // Length lower
					copy(resp[4:8], reqNum)

					logging.Logger.Debug("ICP Query Processed",
						zap.String("from", peerAddr.String()),
						zap.String("url", urlStr),
						zap.Bool("hit", hit))

					outcome := "miss"
					if hit {
						outcome = "hit"
					}
					visibility.RecordPeeringOp(peerAddr.String(), "icp", outcome)

					conn.WriteToUDP(resp, peerAddr)
				}
			}
		}
	}()
	return nil
}

// startHTCPListener listens for HTCP queries (UDP 4827)
func (pm *PeerManager) startHTCPListener() error {
	addr := fmt.Sprintf(":%d", pm.cfg.HTCPPort)
	if addr == ":0" {
		addr = ":4827"
	}

	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return err
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return err
	}
	pm.htcpConn = conn // Store for closing

	logging.Logger.Info("HTCP Listener started", zap.String("addr", addr))

	go func() {
		buf := make([]byte, 16384)
		for {
			select {
			case <-pm.stopChan:
				return
			default:
				conn.SetReadDeadline(time.Now().Add(1 * time.Second))
				n, peerAddr, err := conn.ReadFromUDP(buf)
				if err != nil {
					if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
						continue
					}
					return
				}

				// Basic HTCP Header parsing (RFC 2756)
				// Header length: 2 bytes
				if n < 6 {
					continue
				}

				// hl := binary.BigEndian.Uint16(buf[0:2])
				// major := buf[2]
				// minor := buf[3]
				// dl := binary.BigEndian.Uint16(buf[4:6])

				// Data starts at 6 + header_offset? No, HL includes data? No.
				// RFC: Header is HL bytes.
				// Data follows header.

				// For now, logging stub for TST (Opcode 0)
				// We won't implement full HTCP this round as ICP is primary.
				// But we acknowledge receipt.

				logging.Logger.Debug("Received HTCP Packet (Not fully implemented)",
					zap.String("from", peerAddr.String()),
					zap.Int("len", n))
			}
		}
	}()
	return nil
}

// Shutdown stops the listeners and background routines
func (pm *PeerManager) Shutdown(ctx context.Context) error {
	pm.stopOnce.Do(func() {
		close(pm.stopChan)
	})
	if pm.icpConn != nil {
		pm.icpConn.Close()
	}
	if pm.htcpConn != nil {
		pm.htcpConn.Close()
	}
	return nil
}
