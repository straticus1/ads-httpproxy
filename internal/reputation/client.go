package reputation

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"ads-httpproxy/pkg/logging"

	"go.uber.org/zap"
)

// Response matches the JSON structure from the Python service
type Response struct {
	URL        string   `json:"url"`
	Blocked    bool     `json:"blocked"`
	Score      float64  `json:"score"`
	RiskLevel  string   `json:"risk_level"`
	Categories []string `json:"categories"`
	Sources    []string `json:"sources"`
}

type cachedResponse struct {
	Response  *Response
	CommandAt time.Time
}

type Client struct {
	baseURL    string
	httpClient *http.Client
	failOpen   bool
	cache      sync.Map
	ttl        time.Duration
}

// NewClient creates a new Reputation Service client
func NewClient(baseURL string, timeoutMs int, failOpen bool) *Client {
	return &Client{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: time.Duration(timeoutMs) * time.Millisecond,
		},
		failOpen: failOpen,
		ttl:      5 * time.Minute, // Default TTL
	}
}

// Check queries the reputation service for a URL
func (c *Client) Check(ctx context.Context, targetURL string) (*Response, error) {
	// Check Cache
	if val, ok := c.cache.Load(targetURL); ok {
		entry := val.(*cachedResponse)
		if time.Since(entry.CommandAt) < c.ttl {
			return entry.Response, nil
		}
		c.cache.Delete(targetURL)
	}

	apiURL := fmt.Sprintf("%s/check?url=%s", c.baseURL, url.QueryEscape(targetURL))

	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		// Log error but respect failOpen strategy in caller or here
		logging.Logger.Error("Reputation check failed", zap.Error(err), zap.String("url", targetURL))
		if c.failOpen {
			return &Response{URL: targetURL, Blocked: false, RiskLevel: "unknown"}, nil
		}
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		err := fmt.Errorf("reputation service returned status %d", resp.StatusCode)
		logging.Logger.Error("Reputation service error", zap.Error(err))
		if c.failOpen {
			return &Response{URL: targetURL, Blocked: false, RiskLevel: "unknown"}, nil
		}
		return nil, err
	}

	var result Response
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		logging.Logger.Error("Failed to decode reputation response", zap.Error(err))
		if c.failOpen {
			return &Response{URL: targetURL, Blocked: false, RiskLevel: "unknown"}, nil
		}
		return nil, err
	}

	// Cache Success
	c.cache.Store(targetURL, &cachedResponse{
		Response:  &result,
		CommandAt: time.Now(),
	})

	return &result, nil
}
