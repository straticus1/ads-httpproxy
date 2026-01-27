package visibility

import (
	"sync"
	"sync/atomic"
	"time"
)

// Stats holds real-time proxy statistics.
type Stats struct {
	ActiveConnections  int64
	TotalRequests      int64
	TotalBytesSent     int64
	TotalBytesReceived int64
	StartTime          time.Time

	mu sync.RWMutex
}

var globalStats = &Stats{
	StartTime: time.Now(),
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

func IncActiveConnections() {
	atomic.AddInt64(&globalStats.ActiveConnections, 1)
}

func DecActiveConnections() {
	atomic.AddInt64(&globalStats.ActiveConnections, -1)
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
