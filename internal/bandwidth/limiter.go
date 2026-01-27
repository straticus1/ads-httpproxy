package bandwidth

import (
	"context"
	"io"

	"golang.org/x/time/rate"
)

// Limiter provides bandwidth rate limiting using a token bucket.
type Limiter struct {
	limiter *rate.Limiter
}

// NewLimiter creates a new bandwidth limiter.
// limit is bytes per second.
// burst is the maximum burst size in bytes.
func NewLimiter(limit float64, burst int) *Limiter {
	return &Limiter{
		limiter: rate.NewLimiter(rate.Limit(limit), burst),
	}
}

// WaitN blocks until n bytes can be allowed.
func (l *Limiter) WaitN(ctx context.Context, n int) error {
	return l.limiter.WaitN(ctx, n)
}

// LimitedReader wraps an io.Reader with a rate limiter.
type LimitedReader struct {
	R       io.Reader
	Limiter *Limiter
	Ctx     context.Context
}

func (r *LimitedReader) Read(p []byte) (n int, err error) {
	n, err = r.R.Read(p)
	if n > 0 && r.Limiter != nil {
		if r.Ctx == nil {
			r.Ctx = context.Background()
		}
		// Wait for permission to return n bytes
		if waitErr := r.Limiter.WaitN(r.Ctx, n); waitErr != nil {
			// If context is canceled or error occurs, we still return the bytes read
			// but also the error.
			return n, waitErr
		}
	}
	return n, err
}

// LimitedReadCloser wraps an io.ReadCloser with a rate limiter.
type LimitedReadCloser struct {
	RC      io.ReadCloser
	Limiter *Limiter
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
	Limiter *Limiter
	Ctx     context.Context
}

func (w *LimitedWriter) Write(p []byte) (n int, err error) {
	if w.Limiter != nil {
		if w.Ctx == nil {
			w.Ctx = context.Background()
		}
		// Wait before writing
		if err := w.Limiter.WaitN(w.Ctx, len(p)); err != nil {
			return 0, err
		}
	}
	return w.W.Write(p)
}
