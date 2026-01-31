package bandwidth

import (
	"context"
	"io"
	"time"

	"github.com/go-redis/redis/v8"
	"golang.org/x/time/rate"
)

// Limiter interface abstracts local vs distributed limiting
type Limiter interface {
	WaitN(ctx context.Context, n int) error
}

// LocalLimiter uses in-memory token bucket
type LocalLimiter struct {
	limiter *rate.Limiter
}

func NewLocalLimiter(limit float64, burst int) *LocalLimiter {
	return &LocalLimiter{
		limiter: rate.NewLimiter(rate.Limit(limit), burst),
	}
}

func (l *LocalLimiter) WaitN(ctx context.Context, n int) error {
	return l.limiter.WaitN(ctx, n)
}

// DistributedLimiter uses Redis for global rate limiting
type DistributedLimiter struct {
	client *redis.Client
	key    string
	rate   float64
	burst  int
}

func NewDistributedLimiter(client *redis.Client, key string, limit float64, burst int) *DistributedLimiter {
	return &DistributedLimiter{
		client: client,
		key:    key,
		rate:   limit,
		burst:  burst,
	}
}

// luaScript implements a Token Bucket in Redis
// KeysPerSlot is not strictly enforced in cluster unless using hashtags, but for single key it's fine.
var luaScript = redis.NewScript(`
local tokens_key = KEYS[1]
local timestamp_key = KEYS[2]
local rate = tonumber(ARGV[1])
local capacity = tonumber(ARGV[2])
local now = tonumber(ARGV[3])
local requested = tonumber(ARGV[4])

local fill_time = capacity / rate
local ttl = math.floor(fill_time * 2)

local last_tokens = tonumber(redis.call("get", tokens_key))
if last_tokens == nil then
  last_tokens = capacity
end

local last_refreshed = tonumber(redis.call("get", timestamp_key))
if last_refreshed == nil then
  last_refreshed = 0
end

local delta = math.max(0, now - last_refreshed)
local filled_tokens = math.min(capacity, last_tokens + (delta * rate))
local allowed = filled_tokens >= requested
local new_tokens = filled_tokens
if allowed then
  new_tokens = filled_tokens - requested
end

redis.call("setex", tokens_key, ttl, new_tokens)
redis.call("setex", timestamp_key, ttl, now)

return allowed
`)

func (d *DistributedLimiter) WaitN(ctx context.Context, n int) error {
	// Simple spin-wait for distributed token bucket
	// In production, you'd want a more sophisticated backoff or reservation system.
	// This "Spin" is aggressive but demonstrates the logic.
	// Exponential backoff
	delay := 10 * time.Millisecond
	maxDelay := 500 * time.Millisecond

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
			now := float64(time.Now().UnixNano()) / 1e9
			allowed, err := luaScript.Run(ctx, d.client, []string{d.key + "_tokens", d.key + "_ts"}, d.rate, d.burst, now, n).Bool()
			if err != nil {
				return err
			}
			if allowed {
				return nil
			}
			// Increase delay
			delay *= 2
			if delay > maxDelay {
				delay = maxDelay
			}
		}
	}
}

// LimitedReader wraps an io.Reader with a rate limiter.
type LimitedReader struct {
	R       io.Reader
	Limiter Limiter
	Ctx     context.Context
}

func (r *LimitedReader) Read(p []byte) (n int, err error) {
	n, err = r.R.Read(p)
	if n > 0 && r.Limiter != nil {
		if r.Ctx == nil {
			r.Ctx = context.Background()
		}
		if waitErr := r.Limiter.WaitN(r.Ctx, n); waitErr != nil {
			return n, waitErr
		}
	}
	return n, err
}

// LimitedReadCloser wraps an io.ReadCloser with a rate limiter.
type LimitedReadCloser struct {
	RC      io.ReadCloser
	Limiter Limiter
	Ctx     context.Context
}

func (r *LimitedReadCloser) Read(p []byte) (n int, err error) {
	n, err = r.RC.Read(p)
	if n > 0 && r.Limiter != nil {
		if r.Ctx == nil {
			r.Ctx = context.Background()
		}
		if waitErr := r.Limiter.WaitN(r.Ctx, n); waitErr != nil {
			return n, waitErr
		}
	}
	return n, err
}

func (r *LimitedReadCloser) Close() error {
	return r.RC.Close()
}

// LimitedWriter wraps an io.Writer with a rate limiter.
type LimitedWriter struct {
	W       io.Writer
	Limiter Limiter
	Ctx     context.Context
}

func (w *LimitedWriter) Write(p []byte) (n int, err error) {
	if w.Limiter != nil {
		if w.Ctx == nil {
			w.Ctx = context.Background()
		}
		if err := w.Limiter.WaitN(w.Ctx, len(p)); err != nil {
			return 0, err
		}
	}
	return w.W.Write(p)
}
