package screenshot

import (
	"context"
	"fmt"
	"strings"
	"time"

	"ads-httpproxy/pkg/logging"

	"go.uber.org/zap"

	"github.com/chromedp/chromedp"
)

// Service handles capturing screenshots using Headless Chrome
type Service struct {
	allocCtx context.Context
	cancel   context.CancelFunc
}

func NewService() *Service {
	// Create allocator context once (starts/manages chrome instance)
	// Default options find Chrome on the system
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.DisableGPU,
		chromedp.Headless,
	)

	allocCtx, cancel := chromedp.NewExecAllocator(context.Background(), opts...)

	// Force start Chrome immediately so we don't wait on first request?
	// Not strictly necessary, but helpful.
	// Actually we should keep the allocator open.

	return &Service{
		allocCtx: allocCtx,
		cancel:   cancel,
	}
}

// Shutdown closes the Chrome instance
func (s *Service) Shutdown() {
	if s.cancel != nil {
		s.cancel()
	}
}

// Capture takes a screenshot of the specified URL
// Returns the PNG bytes or an error
func (s *Service) Capture(ctx context.Context, targetURL string) ([]byte, error) {
	// Security: Whitelist schemes
	if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
		return nil, fmt.Errorf("invalid url scheme: %s", targetURL)
	}

	// Create context with timeout
	// Note: We derive from allocCtx to trigger browser, BUT we want the *timeout* from the request context?
	// Actually chromedp.NewContext takes a parent. We use s.allocCtx as parent.

	taskCtx, cancelTask := chromedp.NewContext(s.allocCtx)
	defer cancelTask()

	// Apply timeout to the task context
	taskCtx, cancelTimeout := context.WithTimeout(taskCtx, 15*time.Second)
	defer cancelTimeout()

	var buf []byte

	logging.Logger.Debug("Capturing screenshot", zap.String("url", targetURL))

	// Run tasks
	// Note: If allocCtx is cancelled (Shutdown), this fails immediately.
	err := chromedp.Run(taskCtx,
		chromedp.Navigate(targetURL),
		chromedp.Sleep(2*time.Second),     // Wait for render/animations
		chromedp.FullScreenshot(&buf, 90), // 90% quality
	)

	if err != nil {
		logging.Logger.Error("Screenshot failed", zap.String("url", targetURL), zap.Error(err))
		return nil, err
	}

	logging.Logger.Info("Screenshot captured",
		zap.String("url", targetURL),
		zap.Int("size_bytes", len(buf)))

	return buf, nil
}
