package visibility

import (
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// ConnectionInfo holds details about an active connection.
type ConnectionInfo struct {
	ID        string    `json:"id"`
	Remote    string    `json:"remote"`
	StartTime time.Time `json:"start_time"`
}

// Stats holds real-time proxy statistics.
type Stats struct {
	ActiveConnections  int64
	TotalRequests      int64
	TotalBytesSent     int64
	TotalBytesReceived int64
	StartTime          time.Time

	mu          sync.RWMutex
	Connections map[string]*ConnectionInfo
}

var globalStats = &Stats{
	StartTime:   time.Now(),
	Connections: make(map[string]*ConnectionInfo),
}

// StatsSnapshot holds a point-in-time snapshot of stats.
type StatsSnapshot struct {
	ActiveConnections  int64  `json:"active_connections"`
	TotalRequests      int64  `json:"total_requests"`
	TotalBytesSent     int64  `json:"total_bytes_sent"`
	TotalBytesReceived int64  `json:"total_bytes_received"`
	Uptime             string `json:"uptime"`
}

// GetStats returns a snapshot of the current stats.
func GetStats() StatsSnapshot {
	globalStats.mu.RLock()
	defer globalStats.mu.RUnlock()
	return StatsSnapshot{
		ActiveConnections:  atomic.LoadInt64(&globalStats.ActiveConnections),
		TotalRequests:      atomic.LoadInt64(&globalStats.TotalRequests),
		TotalBytesSent:     atomic.LoadInt64(&globalStats.TotalBytesSent),
		TotalBytesReceived: atomic.LoadInt64(&globalStats.TotalBytesReceived),
		Uptime:             time.Since(globalStats.StartTime).String(),
	}
}

// GetActiveConnections returns a list of currently active connections.
func GetActiveConnections() []ConnectionInfo {
	globalStats.mu.RLock()
	defer globalStats.mu.RUnlock()
	conns := make([]ConnectionInfo, 0, len(globalStats.Connections))
	for _, c := range globalStats.Connections {
		conns = append(conns, *c)
	}
	return conns
}

func RegisterConnection(c net.Conn) string {
	info := &ConnectionInfo{
		ID:        c.RemoteAddr().String(), // Simple ID for now
		Remote:    c.RemoteAddr().String(),
		StartTime: time.Now(),
	}

	globalStats.mu.Lock()
	defer globalStats.mu.Unlock()

	globalStats.Connections[info.ID] = info
	atomic.AddInt64(&globalStats.ActiveConnections, 1)
	return info.ID
}

func UnregisterConnection(id string) {
	globalStats.mu.Lock()
	defer globalStats.mu.Unlock()

	if _, ok := globalStats.Connections[id]; ok {
		delete(globalStats.Connections, id)
		atomic.AddInt64(&globalStats.ActiveConnections, -1)
	}
}

func IncTotalRequests() {
	atomic.AddInt64(&globalStats.TotalRequests, 1)
}

func AddBytesSent(n int64) {
	atomic.AddInt64(&globalStats.TotalBytesSent, n)
}

func AddBytesReceived(n int64) {
	atomic.AddInt64(&globalStats.TotalBytesReceived, n)
}
