package cache

import (
	"context"
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
