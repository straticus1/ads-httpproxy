package accounting

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"ads-httpproxy/pkg/logging"
	"go.uber.org/zap"
)

// Accounting tracks per-user bandwidth, traffic patterns, and compliance data
// for regulated environments (GDPR, HIPAA, SOX, PCI-DSS, etc.)
type Accounting struct {
	storage   Storage
	mu        sync.RWMutex
	users     map[string]*UserAccounting
	retention time.Duration
}

// UserAccounting tracks all metrics for a single user
type UserAccounting struct {
	UserID         string
	Username       string
	IPAddress      string
	SessionID      string
	mu             sync.RWMutex

	// Bandwidth metrics (atomic for lockless updates)
	BytesIn        atomic.Uint64  // Bytes received from user
	BytesOut       atomic.Uint64  // Bytes sent to user
	Requests       atomic.Uint64  // Total requests
	Blocked        atomic.Uint64  // Blocked requests

	// Time tracking
	FirstSeen      time.Time
	LastSeen       atomic.Value   // time.Time
	Duration       atomic.Int64   // Session duration in seconds

	// Category tracking
	Categories     sync.Map       // map[string]*CategoryStats

	// Detailed logs (for audit trail)
	Events         []Event
	eventMu        sync.Mutex
}

// CategoryStats tracks bandwidth per traffic category
type CategoryStats struct {
	Category  string
	BytesIn   atomic.Uint64
	BytesOut  atomic.Uint64
	Requests  atomic.Uint64
	Blocked   atomic.Uint64
	LastAccess atomic.Value // time.Time
}

// Event represents a single user activity for audit trail
type Event struct {
	Timestamp    time.Time
	UserID       string
	Username     string
	IPAddress    string
	SessionID    string
	Method       string
	URL          string
	Host         string
	Category     string       // e.g., "social_media", "video", "banking"
	Action       string       // "allow", "block", "modify"
	Reason       string       // Why blocked/modified
	BytesIn      uint64
	BytesOut     uint64
	Duration     time.Duration
	StatusCode   int
	UserAgent    string
	TLS          bool
	TLSVersion   string
	Cipher       string

	// Compliance fields
	DataClass      string       // "public", "internal", "confidential", "pii", "phi"
	GeoLocation    string       // Country/region
	DLPMatches     []string     // DLP patterns matched
	ThreatScore    int          // 0-100
	VirusDetected  bool
	VirusName      string

	// Custom metadata
	Tags         map[string]string
}

// Storage interface for persisting accounting data
type Storage interface {
	SaveEvent(ctx context.Context, event *Event) error
	SaveUserStats(ctx context.Context, userID string, stats *UserAccounting) error
	GetUserStats(ctx context.Context, userID string, from, to time.Time) (*UserAccounting, error)
	GetEvents(ctx context.Context, userID string, from, to time.Time) ([]Event, error)
	GetTopUsers(ctx context.Context, metric string, limit int, from, to time.Time) ([]UserStats, error)
	GetCategoryStats(ctx context.Context, userID string, from, to time.Time) (map[string]*CategoryStats, error)
	Cleanup(ctx context.Context, before time.Time) error
}

// UserStats for reporting
type UserStats struct {
	UserID    string
	Username  string
	BytesIn   uint64
	BytesOut  uint64
	Requests  uint64
	Duration  time.Duration
}

// NewAccounting creates a new accounting tracker
func NewAccounting(storage Storage, retention time.Duration) *Accounting {
	a := &Accounting{
		storage:   storage,
		users:     make(map[string]*UserAccounting),
		retention: retention,
	}

	// Start cleanup goroutine
	go a.cleanupLoop()

	return a
}

// RecordRequest records a completed request with full details
func (a *Accounting) RecordRequest(ctx context.Context, event *Event) error {
	// Get or create user accounting
	user := a.getOrCreateUser(event.UserID, event.Username, event.IPAddress, event.SessionID)

	// Update atomic counters
	user.BytesIn.Add(event.BytesIn)
	user.BytesOut.Add(event.BytesOut)
	user.Requests.Add(1)

	if event.Action == "block" {
		user.Blocked.Add(1)
	}

	// Update last seen
	user.LastSeen.Store(event.Timestamp)

	// Update category stats
	if event.Category != "" {
		cat := user.getOrCreateCategory(event.Category)
		cat.BytesIn.Add(event.BytesIn)
		cat.BytesOut.Add(event.BytesOut)
		cat.Requests.Add(1)
		if event.Action == "block" {
			cat.Blocked.Add(1)
		}
		cat.LastAccess.Store(event.Timestamp)
	}

	// Store event for audit trail
	user.eventMu.Lock()
	user.Events = append(user.Events, *event)
	user.eventMu.Unlock()

	// Persist to storage (async)
	go func() {
		if err := a.storage.SaveEvent(context.Background(), event); err != nil {
			logging.Logger.Error("Failed to save accounting event",
				zap.String("user", event.UserID),
				zap.Error(err))
		}
	}()

	return nil
}

// getOrCreateUser retrieves or creates user accounting entry
func (a *Accounting) getOrCreateUser(userID, username, ip, sessionID string) *UserAccounting {
	a.mu.RLock()
	user, exists := a.users[userID]
	a.mu.RUnlock()

	if exists {
		return user
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	// Double-check after acquiring write lock
	if user, exists := a.users[userID]; exists {
		return user
	}

	// Create new user
	now := time.Now()
	user = &UserAccounting{
		UserID:    userID,
		Username:  username,
		IPAddress: ip,
		SessionID: sessionID,
		FirstSeen: now,
		Events:    make([]Event, 0, 1000), // Pre-allocate
	}
	user.LastSeen.Store(now)

	a.users[userID] = user

	logging.Logger.Info("New user session",
		zap.String("user_id", userID),
		zap.String("username", username),
		zap.String("ip", ip))

	return user
}

// getOrCreateCategory retrieves or creates category stats
func (u *UserAccounting) getOrCreateCategory(category string) *CategoryStats {
	if val, ok := u.Categories.Load(category); ok {
		return val.(*CategoryStats)
	}

	cat := &CategoryStats{
		Category: category,
	}
	cat.LastAccess.Store(time.Now())

	u.Categories.Store(category, cat)
	return cat
}

// GetUserStats retrieves current stats for a user
func (a *Accounting) GetUserStats(userID string) (*UserAccounting, error) {
	a.mu.RLock()
	user, exists := a.users[userID]
	a.mu.RUnlock()

	if !exists {
		return nil, ErrUserNotFound
	}

	return user, nil
}

// GetTopUsers returns top N users by specified metric
func (a *Accounting) GetTopUsers(metric string, limit int) []UserStats {
	a.mu.RLock()
	defer a.mu.RUnlock()

	stats := make([]UserStats, 0, len(a.users))

	for _, user := range a.users {
		lastSeen := user.LastSeen.Load().(time.Time)
		duration := lastSeen.Sub(user.FirstSeen)

		stats = append(stats, UserStats{
			UserID:   user.UserID,
			Username: user.Username,
			BytesIn:  user.BytesIn.Load(),
			BytesOut: user.BytesOut.Load(),
			Requests: user.Requests.Load(),
			Duration: duration,
		})
	}

	// Sort by metric
	// TODO: Implement sorting based on metric parameter

	if len(stats) > limit {
		stats = stats[:limit]
	}

	return stats
}

// GetCategoryBreakdown returns bandwidth breakdown by category for a user
func (a *Accounting) GetCategoryBreakdown(userID string) map[string]*CategoryStats {
	a.mu.RLock()
	user, exists := a.users[userID]
	a.mu.RUnlock()

	if !exists {
		return nil
	}

	breakdown := make(map[string]*CategoryStats)
	user.Categories.Range(func(key, value interface{}) bool {
		category := key.(string)
		stats := value.(*CategoryStats)
		breakdown[category] = stats
		return true
	})

	return breakdown
}

// FlushUser persists user data and removes from memory
func (a *Accounting) FlushUser(ctx context.Context, userID string) error {
	a.mu.Lock()
	user, exists := a.users[userID]
	if exists {
		delete(a.users, userID)
	}
	a.mu.Unlock()

	if !exists {
		return ErrUserNotFound
	}

	// Persist to storage
	return a.storage.SaveUserStats(ctx, userID, user)
}

// cleanupLoop periodically flushes old user data
func (a *Accounting) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		a.cleanup()
	}
}

// cleanup flushes inactive users
func (a *Accounting) cleanup() {
	now := time.Now()
	threshold := now.Add(-a.retention)

	a.mu.Lock()
	defer a.mu.Unlock()

	for userID, user := range a.users {
		lastSeen := user.LastSeen.Load().(time.Time)

		if lastSeen.Before(threshold) {
			// Persist and remove
			go func(uid string, u *UserAccounting) {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()

				if err := a.storage.SaveUserStats(ctx, uid, u); err != nil {
					logging.Logger.Error("Failed to save user stats during cleanup",
						zap.String("user", uid),
						zap.Error(err))
				}
			}(userID, user)

			delete(a.users, userID)

			logging.Logger.Info("Flushed inactive user",
				zap.String("user_id", userID),
				zap.Time("last_seen", lastSeen))
		}
	}
}

// GenerateReport creates a compliance report for a user
func (a *Accounting) GenerateReport(ctx context.Context, userID string, from, to time.Time) (*ComplianceReport, error) {
	// Fetch from storage
	stats, err := a.storage.GetUserStats(ctx, userID, from, to)
	if err != nil {
		return nil, err
	}

	events, err := a.storage.GetEvents(ctx, userID, from, to)
	if err != nil {
		return nil, err
	}

	categoryStats, err := a.storage.GetCategoryStats(ctx, userID, from, to)
	if err != nil {
		return nil, err
	}

	report := &ComplianceReport{
		UserID:       userID,
		Username:     stats.Username,
		Period:       Period{From: from, To: to},
		TotalBytesIn: stats.BytesIn.Load(),
		TotalBytesOut: stats.BytesOut.Load(),
		TotalRequests: stats.Requests.Load(),
		BlockedRequests: stats.Blocked.Load(),
		Categories:   categoryStats,
		Events:       events,
		GeneratedAt:  time.Now(),
	}

	return report, nil
}

// ComplianceReport for regulated environments
type ComplianceReport struct {
	UserID          string
	Username        string
	Period          Period
	TotalBytesIn    uint64
	TotalBytesOut   uint64
	TotalRequests   uint64
	BlockedRequests uint64
	Categories      map[string]*CategoryStats
	Events          []Event
	GeneratedAt     time.Time
}

// Period represents a time range
type Period struct {
	From time.Time
	To   time.Time
}

// Errors
var (
	ErrUserNotFound = fmt.Errorf("user not found")
)

// Helper to format bytes
func FormatBytes(bytes uint64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := uint64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}
