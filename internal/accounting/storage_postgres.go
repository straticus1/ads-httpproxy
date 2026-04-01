package accounting

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	_ "github.com/lib/pq"
	"ads-httpproxy/pkg/logging"
	"go.uber.org/zap"
)

// PostgresStorage implements Storage interface with PostgreSQL
type PostgresStorage struct {
	db *sql.DB
}

// NewPostgresStorage creates a new PostgreSQL storage backend
func NewPostgresStorage(dsn string) (*PostgresStorage, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to postgres: %w", err)
	}

	// Configure connection pool
	db.SetMaxOpenConns(100)
	db.SetMaxIdleConns(10)
	db.SetConnMaxLifetime(time.Hour)

	// Test connection
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping postgres: %w", err)
	}

	s := &PostgresStorage{db: db}

	// Create tables if they don't exist
	if err := s.createTables(); err != nil {
		return nil, fmt.Errorf("failed to create tables: %w", err)
	}

	return s, nil
}

// createTables creates the necessary database schema
func (s *PostgresStorage) createTables() error {
	schema := `
	-- User sessions and aggregated stats
	CREATE TABLE IF NOT EXISTS user_sessions (
		user_id TEXT NOT NULL,
		username TEXT,
		session_id TEXT NOT NULL,
		ip_address INET,
		first_seen TIMESTAMPTZ NOT NULL,
		last_seen TIMESTAMPTZ NOT NULL,
		bytes_in BIGINT DEFAULT 0,
		bytes_out BIGINT DEFAULT 0,
		requests BIGINT DEFAULT 0,
		blocked BIGINT DEFAULT 0,
		duration_seconds BIGINT DEFAULT 0,
		PRIMARY KEY (user_id, session_id)
	);

	CREATE INDEX IF NOT EXISTS idx_user_sessions_user_id ON user_sessions(user_id);
	CREATE INDEX IF NOT EXISTS idx_user_sessions_last_seen ON user_sessions(last_seen);

	-- Detailed event log for audit trail
	CREATE TABLE IF NOT EXISTS accounting_events (
		id BIGSERIAL PRIMARY KEY,
		timestamp TIMESTAMPTZ NOT NULL,
		user_id TEXT NOT NULL,
		username TEXT,
		ip_address INET,
		session_id TEXT,
		method TEXT,
		url TEXT,
		host TEXT,
		category TEXT,
		action TEXT,
		reason TEXT,
		bytes_in BIGINT DEFAULT 0,
		bytes_out BIGINT DEFAULT 0,
		duration_ms BIGINT DEFAULT 0,
		status_code INTEGER,
		user_agent TEXT,
		tls BOOLEAN DEFAULT FALSE,
		tls_version TEXT,
		cipher TEXT,
		data_class TEXT,
		geo_location TEXT,
		dlp_matches TEXT[],
		threat_score INTEGER DEFAULT 0,
		virus_detected BOOLEAN DEFAULT FALSE,
		virus_name TEXT,
		tags JSONB
	);

	CREATE INDEX IF NOT EXISTS idx_events_user_id ON accounting_events(user_id);
	CREATE INDEX IF NOT EXISTS idx_events_timestamp ON accounting_events(timestamp);
	CREATE INDEX IF NOT EXISTS idx_events_category ON accounting_events(category);
	CREATE INDEX IF NOT EXISTS idx_events_action ON accounting_events(action);
	CREATE INDEX IF NOT EXISTS idx_events_user_timestamp ON accounting_events(user_id, timestamp);

	-- Category statistics per user
	CREATE TABLE IF NOT EXISTS category_stats (
		user_id TEXT NOT NULL,
		category TEXT NOT NULL,
		bytes_in BIGINT DEFAULT 0,
		bytes_out BIGINT DEFAULT 0,
		requests BIGINT DEFAULT 0,
		blocked BIGINT DEFAULT 0,
		last_access TIMESTAMPTZ NOT NULL,
		PRIMARY KEY (user_id, category)
	);

	CREATE INDEX IF NOT EXISTS idx_category_stats_user ON category_stats(user_id);

	-- User policies (for snoop control, bandwidth limits, etc.)
	CREATE TABLE IF NOT EXISTS user_policies (
		user_id TEXT PRIMARY KEY,
		username TEXT,
		snoop_enabled BOOLEAN DEFAULT FALSE,
		bandwidth_limit_mbps INTEGER DEFAULT 0,
		allowed_categories TEXT[],
		blocked_categories TEXT[],
		created_at TIMESTAMPTZ DEFAULT NOW(),
		updated_at TIMESTAMPTZ DEFAULT NOW()
	);

	CREATE INDEX IF NOT EXISTS idx_user_policies_snoop ON user_policies(snoop_enabled);
	`

	_, err := s.db.Exec(schema)
	return err
}

// SaveEvent stores a single event
func (s *PostgresStorage) SaveEvent(ctx context.Context, event *Event) error {
	query := `
		INSERT INTO accounting_events (
			timestamp, user_id, username, ip_address, session_id,
			method, url, host, category, action, reason,
			bytes_in, bytes_out, duration_ms, status_code,
			user_agent, tls, tls_version, cipher,
			data_class, geo_location, dlp_matches,
			threat_score, virus_detected, virus_name, tags
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
			$11, $12, $13, $14, $15, $16, $17, $18, $19,
			$20, $21, $22, $23, $24, $25, $26
		)
	`

	tagsJSON, _ := json.Marshal(event.Tags)
	durationMs := event.Duration.Milliseconds()

	_, err := s.db.ExecContext(ctx, query,
		event.Timestamp, event.UserID, event.Username, event.IPAddress, event.SessionID,
		event.Method, event.URL, event.Host, event.Category, event.Action, event.Reason,
		event.BytesIn, event.BytesOut, durationMs, event.StatusCode,
		event.UserAgent, event.TLS, event.TLSVersion, event.Cipher,
		event.DataClass, event.GeoLocation, event.DLPMatches,
		event.ThreatScore, event.VirusDetected, event.VirusName, tagsJSON,
	)

	return err
}

// SaveUserStats stores aggregated user statistics
func (s *PostgresStorage) SaveUserStats(ctx context.Context, userID string, stats *UserAccounting) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Save session stats
	sessionQuery := `
		INSERT INTO user_sessions (
			user_id, username, session_id, ip_address,
			first_seen, last_seen, bytes_in, bytes_out,
			requests, blocked, duration_seconds
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		ON CONFLICT (user_id, session_id)
		DO UPDATE SET
			last_seen = EXCLUDED.last_seen,
			bytes_in = EXCLUDED.bytes_in,
			bytes_out = EXCLUDED.bytes_out,
			requests = EXCLUDED.requests,
			blocked = EXCLUDED.blocked,
			duration_seconds = EXCLUDED.duration_seconds
	`

	lastSeen := stats.LastSeen.Load().(time.Time)
	duration := lastSeen.Sub(stats.FirstSeen).Seconds()

	_, err = tx.ExecContext(ctx, sessionQuery,
		stats.UserID, stats.Username, stats.SessionID, stats.IPAddress,
		stats.FirstSeen, lastSeen,
		stats.BytesIn.Load(), stats.BytesOut.Load(),
		stats.Requests.Load(), stats.Blocked.Load(), int64(duration),
	)
	if err != nil {
		return err
	}

	// Save category stats
	categoryQuery := `
		INSERT INTO category_stats (
			user_id, category, bytes_in, bytes_out,
			requests, blocked, last_access
		) VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (user_id, category)
		DO UPDATE SET
			bytes_in = category_stats.bytes_in + EXCLUDED.bytes_in,
			bytes_out = category_stats.bytes_out + EXCLUDED.bytes_out,
			requests = category_stats.requests + EXCLUDED.requests,
			blocked = category_stats.blocked + EXCLUDED.blocked,
			last_access = EXCLUDED.last_access
	`

	stats.Categories.Range(func(key, value interface{}) bool {
		category := key.(string)
		cat := value.(*CategoryStats)
		lastAccess := cat.LastAccess.Load().(time.Time)

		_, err = tx.ExecContext(ctx, categoryQuery,
			userID, category,
			cat.BytesIn.Load(), cat.BytesOut.Load(),
			cat.Requests.Load(), cat.Blocked.Load(),
			lastAccess,
		)
		return err == nil
	})

	if err != nil {
		return err
	}

	return tx.Commit()
}

// GetUserStats retrieves aggregated stats for a user
func (s *PostgresStorage) GetUserStats(ctx context.Context, userID string, from, to time.Time) (*UserAccounting, error) {
	query := `
		SELECT username, session_id, ip_address, first_seen, last_seen,
		       bytes_in, bytes_out, requests, blocked
		FROM user_sessions
		WHERE user_id = $1 AND last_seen >= $2 AND last_seen <= $3
		ORDER BY last_seen DESC
		LIMIT 1
	`

	stats := &UserAccounting{
		UserID: userID,
	}

	var bytesIn, bytesOut, requests, blocked uint64
	err := s.db.QueryRowContext(ctx, query, userID, from, to).Scan(
		&stats.Username, &stats.SessionID, &stats.IPAddress,
		&stats.FirstSeen, &stats.LastSeen,
		&bytesIn, &bytesOut, &requests, &blocked,
	)

	if err != nil {
		return nil, err
	}

	stats.BytesIn.Store(bytesIn)
	stats.BytesOut.Store(bytesOut)
	stats.Requests.Store(requests)
	stats.Blocked.Store(blocked)

	return stats, nil
}

// GetEvents retrieves events for a user in a time range
func (s *PostgresStorage) GetEvents(ctx context.Context, userID string, from, to time.Time) ([]Event, error) {
	query := `
		SELECT timestamp, user_id, username, ip_address, session_id,
		       method, url, host, category, action, reason,
		       bytes_in, bytes_out, duration_ms, status_code,
		       user_agent, tls, tls_version, cipher,
		       data_class, geo_location, dlp_matches,
		       threat_score, virus_detected, virus_name, tags
		FROM accounting_events
		WHERE user_id = $1 AND timestamp >= $2 AND timestamp <= $3
		ORDER BY timestamp DESC
		LIMIT 10000
	`

	rows, err := s.db.QueryContext(ctx, query, userID, from, to)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	events := make([]Event, 0)

	for rows.Next() {
		var event Event
		var durationMs int64
		var tagsJSON []byte

		err := rows.Scan(
			&event.Timestamp, &event.UserID, &event.Username, &event.IPAddress, &event.SessionID,
			&event.Method, &event.URL, &event.Host, &event.Category, &event.Action, &event.Reason,
			&event.BytesIn, &event.BytesOut, &durationMs, &event.StatusCode,
			&event.UserAgent, &event.TLS, &event.TLSVersion, &event.Cipher,
			&event.DataClass, &event.GeoLocation, &event.DLPMatches,
			&event.ThreatScore, &event.VirusDetected, &event.VirusName, &tagsJSON,
		)

		if err != nil {
			logging.Logger.Error("Failed to scan event", zap.Error(err))
			continue
		}

		event.Duration = time.Duration(durationMs) * time.Millisecond

		if len(tagsJSON) > 0 {
			json.Unmarshal(tagsJSON, &event.Tags)
		}

		events = append(events, event)
	}

	return events, nil
}

// GetTopUsers returns top users by specified metric
func (s *PostgresStorage) GetTopUsers(ctx context.Context, metric string, limit int, from, to time.Time) ([]UserStats, error) {
	var orderBy string
	switch metric {
	case "bytes_in":
		orderBy = "SUM(bytes_in) DESC"
	case "bytes_out":
		orderBy = "SUM(bytes_out) DESC"
	case "requests":
		orderBy = "SUM(requests) DESC"
	case "duration":
		orderBy = "SUM(duration_seconds) DESC"
	default:
		orderBy = "SUM(bytes_in + bytes_out) DESC"
	}

	query := fmt.Sprintf(`
		SELECT user_id, username,
		       SUM(bytes_in) as total_bytes_in,
		       SUM(bytes_out) as total_bytes_out,
		       SUM(requests) as total_requests,
		       SUM(duration_seconds) as total_duration
		FROM user_sessions
		WHERE last_seen >= $1 AND last_seen <= $2
		GROUP BY user_id, username
		ORDER BY %s
		LIMIT $3
	`, orderBy)

	rows, err := s.db.QueryContext(ctx, query, from, to, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	stats := make([]UserStats, 0, limit)

	for rows.Next() {
		var stat UserStats
		var durationSecs int64

		err := rows.Scan(
			&stat.UserID, &stat.Username,
			&stat.BytesIn, &stat.BytesOut,
			&stat.Requests, &durationSecs,
		)

		if err != nil {
			continue
		}

		stat.Duration = time.Duration(durationSecs) * time.Second
		stats = append(stats, stat)
	}

	return stats, nil
}

// GetCategoryStats retrieves category breakdown for a user
func (s *PostgresStorage) GetCategoryStats(ctx context.Context, userID string, from, to time.Time) (map[string]*CategoryStats, error) {
	query := `
		SELECT category, bytes_in, bytes_out, requests, blocked, last_access
		FROM category_stats
		WHERE user_id = $1 AND last_access >= $2 AND last_access <= $3
	`

	rows, err := s.db.QueryContext(ctx, query, userID, from, to)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	stats := make(map[string]*CategoryStats)

	for rows.Next() {
		cat := &CategoryStats{}
		var bytesIn, bytesOut, requests, blocked uint64
		var lastAccess time.Time

		err := rows.Scan(
			&cat.Category, &bytesIn, &bytesOut, &requests, &blocked, &lastAccess,
		)

		if err != nil {
			continue
		}

		cat.BytesIn.Store(bytesIn)
		cat.BytesOut.Store(bytesOut)
		cat.Requests.Store(requests)
		cat.Blocked.Store(blocked)
		cat.LastAccess.Store(lastAccess)

		stats[cat.Category] = cat
	}

	return stats, nil
}

// Cleanup removes old records
func (s *PostgresStorage) Cleanup(ctx context.Context, before time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Delete old events
	_, err = tx.ExecContext(ctx, "DELETE FROM accounting_events WHERE timestamp < $1", before)
	if err != nil {
		return err
	}

	// Delete old sessions
	_, err = tx.ExecContext(ctx, "DELETE FROM user_sessions WHERE last_seen < $1", before)
	if err != nil {
		return err
	}

	// Delete old category stats
	_, err = tx.ExecContext(ctx, "DELETE FROM category_stats WHERE last_access < $1", before)
	if err != nil {
		return err
	}

	return tx.Commit()
}

// User Policy Management

// GetUserPolicy retrieves policy for a user (including snoop control)
func (s *PostgresStorage) GetUserPolicy(ctx context.Context, userID string) (*UserPolicy, error) {
	query := `
		SELECT user_id, username, snoop_enabled, bandwidth_limit_mbps,
		       allowed_categories, blocked_categories, created_at, updated_at
		FROM user_policies
		WHERE user_id = $1
	`

	policy := &UserPolicy{}
	err := s.db.QueryRowContext(ctx, query, userID).Scan(
		&policy.UserID, &policy.Username, &policy.SnoopEnabled, &policy.BandwidthLimitMbps,
		&policy.AllowedCategories, &policy.BlockedCategories,
		&policy.CreatedAt, &policy.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		// Return default policy
		return &UserPolicy{
			UserID:       userID,
			SnoopEnabled: false, // Default: no SSL interception
		}, nil
	}

	return policy, err
}

// SetUserPolicy updates policy for a user
func (s *PostgresStorage) SetUserPolicy(ctx context.Context, policy *UserPolicy) error {
	query := `
		INSERT INTO user_policies (
			user_id, username, snoop_enabled, bandwidth_limit_mbps,
			allowed_categories, blocked_categories, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, NOW())
		ON CONFLICT (user_id)
		DO UPDATE SET
			username = EXCLUDED.username,
			snoop_enabled = EXCLUDED.snoop_enabled,
			bandwidth_limit_mbps = EXCLUDED.bandwidth_limit_mbps,
			allowed_categories = EXCLUDED.allowed_categories,
			blocked_categories = EXCLUDED.blocked_categories,
			updated_at = NOW()
	`

	_, err := s.db.ExecContext(ctx, query,
		policy.UserID, policy.Username, policy.SnoopEnabled, policy.BandwidthLimitMbps,
		policy.AllowedCategories, policy.BlockedCategories,
	)

	return err
}

// UserPolicy represents per-user configuration
type UserPolicy struct {
	UserID             string
	Username           string
	SnoopEnabled       bool     // SSL interception for this user
	BandwidthLimitMbps int
	AllowedCategories  []string
	BlockedCategories  []string
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

// Close closes the database connection
func (s *PostgresStorage) Close() error {
	return s.db.Close()
}
