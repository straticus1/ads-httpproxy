package cluster

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"ads-httpproxy/internal/config"
	"ads-httpproxy/pkg/logging"

	"github.com/go-redis/redis/v8"
	"go.uber.org/zap"
)

// EventType defines the kind of sync event
type EventType string

const (
	EventBlockIP      EventType = "block_ip"
	EventUnblockIP    EventType = "unblock_ip"
	EventRateLimit    EventType = "rate_limit"
	EventConfigChange EventType = "config_change"
)

// SyncEvent represents a message broadcast to the cluster
type SyncEvent struct {
	Type      EventType `json:"type"`
	Payload   string    `json:"payload"` // JSON payload depending on Type
	SourceDC  string    `json:"source_dc"`
	Timestamp int64     `json:"timestamp"`
}

// Manager handles cluster synchronization via Redis Pub/Sub
type Manager struct {
	client  *redis.Client
	channel string
	dcName  string
	handler func(Event)
}

type Event struct {
	Type    EventType
	Payload string
}

func NewManager(cfg *config.RedisConfig, dcName string) (*Manager, error) {
	if !cfg.Enabled {
		return nil, nil // Cluster disabled
	}

	rdb := redis.NewClient(&redis.Options{
		Addr:     cfg.Addr,
		Password: cfg.Password,
		DB:       cfg.DB,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := rdb.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("redis connection failed: %w", err)
	}

	return &Manager{
		client:  rdb,
		channel: "ads_proxy_cluster_sync",
		dcName:  dcName,
	}, nil
}

// Subscribe starts listening for cluster events
func (m *Manager) Subscribe(ctx context.Context, handler func(Event)) {
	m.handler = handler
	pubsub := m.client.Subscribe(ctx, m.channel)

	go func() {
		defer pubsub.Close()
		ch := pubsub.Channel()

		for msg := range ch {
			var event SyncEvent
			if err := json.Unmarshal([]byte(msg.Payload), &event); err != nil {
				logging.Logger.Error("Failed to unmarshal sync event", zap.Error(err))
				continue
			}

			// Ignore events from self
			if event.SourceDC == m.dcName {
				continue
			}

			logging.Logger.Debug("Received cluster event",
				zap.String("type", string(event.Type)),
				zap.String("source", event.SourceDC))

			if m.handler != nil {
				m.handler(Event{Type: event.Type, Payload: event.Payload})
			}
		}
	}()
}

// Publish broadcasts an event to the cluster
func (m *Manager) Publish(ctx context.Context, eventType EventType, payload string) error {
	if m.client == nil {
		return nil
	}

	event := SyncEvent{
		Type:      eventType,
		Payload:   payload,
		SourceDC:  m.dcName,
		Timestamp: time.Now().Unix(),
	}

	data, err := json.Marshal(event)
	if err != nil {
		return err
	}

	return m.client.Publish(ctx, m.channel, data).Err()
}
