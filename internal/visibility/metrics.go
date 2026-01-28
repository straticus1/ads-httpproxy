package visibility

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// RequestCounters
	RequestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "ads_proxy_requests_total",
		Help: "The total number of processed requests",
	}, []string{"protocol", "status", "verdict"}) // verdict: allow, block_threat, block_geoip, block_policy

	// Latency
	RequestDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "ads_proxy_request_duration_seconds",
		Help:    "Duration of request processing in seconds",
		Buckets: prometheus.DefBuckets,
	}, []string{"protocol"})

	// Connects
	ActiveConnections = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "ads_proxy_active_connections",
		Help: "Number of currently active connections",
	})

	// Data
	BytesTransferred = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "ads_proxy_bytes_transferred_total",
		Help: "Total bytes transferred",
	}, []string{"direction"}) // up, down
)

func RecordRequest(protocol, status, verdict string) {
	RequestsTotal.WithLabelValues(protocol, status, verdict).Inc()
}

func Connect() {
	ActiveConnections.Inc()
}

func Disconnect() {
	ActiveConnections.Dec()
}
