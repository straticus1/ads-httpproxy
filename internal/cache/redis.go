package cache

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
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
		rdb.Close()
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

// Set is retained for non-HTTP callers. Writes are bounded and synchronous;
// per-response goroutines would permit stale writes after invalidation.
func (m *Manager) Set(key string, value []byte, ttl time.Duration) {
	if err := m.SetSync(key, value, ttl); err != nil {
		logging.Logger.Warn("Redis Set error", zap.Error(err))
	}
}

func (m *Manager) SetSync(key string, value []byte, ttl time.Duration) error {
	if m == nil || ttl <= 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	return m.client.Set(ctx, key, value, ttl).Err()
}

// Epoch and partition tokens have bounded cardinality (257). Missing or evicted
// tokens are recreated randomly: a Redis restart/eviction cannot expose a stale
// L1 namespace by resetting a generation counter to zero.
func (m *Manager) generations(partition byte) (string, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	keys := []string{"cache:generation:v3:epoch", fmt.Sprintf("cache:generation:v3:%d", partition)}
	values, err := m.client.MGet(ctx, keys...).Result()
	if err != nil {
		return "", "", err
	}
	missing := false
	for i, value := range values {
		if value == nil {
			token, err := generationToken()
			if err != nil {
				return "", "", err
			}
			if err := m.client.SetNX(ctx, keys[i], token, 0).Err(); err != nil {
				return "", "", err
			}
			missing = true
		}
	}
	if missing {
		values, err = m.client.MGet(ctx, keys...).Result()
		if err != nil {
			return "", "", err
		}
	}
	if len(values) != 2 || values[0] == nil || values[1] == nil {
		return "", "", errors.New("cache generations unavailable")
	}
	return fmt.Sprint(values[0]), fmt.Sprint(values[1]), nil
}
func generationToken() (string, error) {
	var token [16]byte
	if _, err := rand.Read(token[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(token[:]), nil
}
func (m *Manager) bumpGeneration(partition byte) error {
	return m.bump(fmt.Sprintf("cache:generation:v3:%d", partition))
}
func (m *Manager) bumpEpoch() error { return m.bump("cache:generation:v3:epoch") }
func (m *Manager) bump(key string) error {
	token, err := generationToken()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	return m.client.Set(ctx, key, token, 0).Err()
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
