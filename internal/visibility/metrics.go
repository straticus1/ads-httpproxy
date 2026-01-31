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

	// Security Events
	DLPViolations = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "ads_proxy_dlp_violations_total",
		Help: "Total number of DLP violations detected",
	}, []string{"source", "pattern"}) // source=req/resp

	WAFViolations = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "ads_proxy_waf_violations_total",
		Help: "Total number of WAF violations detected",
	}, []string{"part", "reason"}) // part=url/header

	ReputationBlocked = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "ads_proxy_reputation_blocked_total",
		Help: "Total number of requests blocked by reputation service",
	}, []string{"risk_level"})

	// Peering
	PeeringOps = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "ads_proxy_peering_ops_total",
		Help: "Total peering operations",
	}, []string{"peer", "protocol", "outcome"}) // protocol=icp/htcp, outcome=hit/miss/sent/received
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

func RecordDLPViolation(source, pattern string) {
	DLPViolations.WithLabelValues(source, pattern).Inc()
}

func RecordWAFViolation(part, reason string) {
	WAFViolations.WithLabelValues(part, reason).Inc()
}

func RecordReputationBlock(riskLevel string) {
	ReputationBlocked.WithLabelValues(riskLevel).Inc()
}

func RecordPeeringOp(peer, protocol, outcome string) {
	PeeringOps.WithLabelValues(peer, protocol, outcome).Inc()
}
