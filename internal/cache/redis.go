package cache

import (
	"context"
	"strings"
	"time"

	"ads-httpproxy/internal/config"
	"ads-httpproxy/pkg/logging"

	"github.com/go-redis/redis/v8"
	"go.uber.org/zap"
)

type Manager struct {
	client *redis.Client
}

func NewManager(cfg *config.RedisConfig) *Manager {
	if cfg == nil || !cfg.Enabled {
		return nil
	}

	rdb := redis.NewClient(&redis.Options{
		Addr:     cfg.Addr,
		Password: cfg.Password,
		DB:       cfg.DB,
	})

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := rdb.Ping(ctx).Err(); err != nil {
		logging.Logger.Error("Failed to connect to Redis cache", zap.Error(err))
		return nil
	}

	logging.Logger.Info("Connected to Redis cache", zap.String("addr", cfg.Addr))
	return &Manager{client: rdb}
}

func (m *Manager) Get(key string) ([]byte, bool) {
	if m == nil {
		return nil, false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	val, err := m.client.Get(ctx, key).Result()
	if err == redis.Nil {
		return nil, false
	} else if err != nil {
		logging.Logger.Warn("Redis Get error", zap.Error(err))
		return nil, false
	}
	return []byte(val), true
}

func (m *Manager) Set(key string, value []byte, ttl time.Duration) {
	if m == nil {
		return
	}
	// Don't block heavily on cache sets
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()
		if err := m.client.Set(ctx, key, value, ttl).Err(); err != nil {
			logging.Logger.Warn("Redis Set error", zap.Error(err))
		}
	}()
}

// Delete removes a key from cache
func (m *Manager) Delete(key string) error {
	if m == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	return m.client.Del(ctx, key).Err()
}

// PurgePattern deletes all keys matching a pattern
func (m *Manager) PurgePattern(pattern string) error {
	if m == nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	iter := m.client.Scan(ctx, 0, pattern, 0).Iterator()
	pipe := m.client.Pipeline()

	count := 0
	for iter.Next(ctx) {
		pipe.Del(ctx, iter.Val())
		count++

		// Execute pipeline in batches of 100
		if count%100 == 0 {
			if _, err := pipe.Exec(ctx); err != nil {
				logging.Logger.Warn("Redis pipeline exec error", zap.Error(err))
			}
			pipe = m.client.Pipeline()
		}
	}

	// Execute remaining
	if count%100 != 0 {
		if _, err := pipe.Exec(ctx); err != nil {
			logging.Logger.Warn("Redis pipeline exec error", zap.Error(err))
		}
	}

	if err := iter.Err(); err != nil {
		return err
	}

	logging.Logger.Info("Purged Redis keys", zap.String("pattern", pattern), zap.Int("count", count))
	return nil
}

// Stats returns Redis statistics
func (m *Manager) Stats() (map[string]string, error) {
	if m == nil {
		return nil, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	info, err := m.client.Info(ctx, "stats", "memory").Result()
	if err != nil {
		return nil, err
	}

	stats := make(map[string]string)
	lines := strings.Split(info, "\r\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			stats[parts[0]] = parts[1]
		}
	}

	return stats, nil
}

// Close closes the Redis connection
func (m *Manager) Close() error {
	if m == nil || m.client == nil {
		return nil
	}
	return m.client.Close()
}
