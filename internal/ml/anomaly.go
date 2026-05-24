package ml

import (
	"math"
	"sync"
	"time"

	"ads-httpproxy/pkg/logging"
	"go.uber.org/zap"
)

// AnomalyMonitor tracks requests to provide real-time Z-Score anomaly detection.
type AnomalyMonitor struct {
	mu           sync.RWMutex
	ipStats      map[string][]int64 // Tracks request timestamps per IP
	windowSize   time.Duration
	alertThreshold float64 // Z-Score threshold (e.g., 3.0)
}

func NewAnomalyMonitor() *AnomalyMonitor {
	m := &AnomalyMonitor{
		ipStats:      make(map[string][]int64),
		windowSize:   5 * time.Minute,
		alertThreshold: 3.0,
	}
	go m.cleanupLoop()
	return m
}

// Track registers a hit and returns true if it represents an anomaly.
func (m *AnomalyMonitor) Track(ip string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now().Unix()
	
	if _, exists := m.ipStats[ip]; !exists {
		m.ipStats[ip] = []int64{now}
		return false
	}
	
	m.ipStats[ip] = append(m.ipStats[ip], now)
	
	// Fast-path prune (only keeping last 5 mins)
	cutoff := now - int64(m.windowSize.Seconds())
	var valid []int64
	for _, t := range m.ipStats[ip] {
		if t >= cutoff {
			valid = append(valid, t)
		}
	}
	m.ipStats[ip] = valid

	// Perform basic deviation check (Z-Score approximation on volume)
	// For production: This requires a rolling baseline, but for a simple proxy we 
	// can calculate instantaneous burst rate vs average network rate.
	return m.checkAnomaly(ip, len(valid))
}

func (m *AnomalyMonitor) checkAnomaly(ip string, currentCount int) bool {
	if currentCount < 50 { 
		// Too little data to be anomalous
		return false 
	}

	// Calculate system-wide mean
	var totalCounts, ips int
	for _, timestamps := range m.ipStats {
		totalCounts += len(timestamps)
		ips++
	}

	if ips <= 1 {
		return false // Can't compare against network baseline if only 1 IP
	}

	mean := float64(totalCounts) / float64(ips)
	
	// Calculate Standard Deviation
	var varianceSum float64
	for _, timestamps := range m.ipStats {
		diff := float64(len(timestamps)) - mean
		varianceSum += diff * diff
	}
	stdDev := math.Sqrt(varianceSum / float64(ips))

	if stdDev == 0 {
		return false
	}

	// Calculate Z-Score
	zScore := (float64(currentCount) - mean) / stdDev

	if zScore > m.alertThreshold {
		logging.Logger.Warn("ML Anomaly Detected: Traffic burst", 
			zap.String("ip", ip), 
			zap.Float64("z_score", zScore),
			zap.Int("current_reqs", currentCount),
		)
		return true
	}

	return false
}

func (m *AnomalyMonitor) cleanupLoop() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		m.mu.Lock()
		now := time.Now().Unix()
		cutoff := now - int64(m.windowSize.Seconds())
		
		for ip, timestamps := range m.ipStats {
			var valid []int64
			for _, t := range timestamps {
				if t >= cutoff {
					valid = append(valid, t)
				}
			}
			if len(valid) == 0 {
				delete(m.ipStats, ip)
			} else {
				m.ipStats[ip] = valid
			}
		}
		m.mu.Unlock()
	}
}
