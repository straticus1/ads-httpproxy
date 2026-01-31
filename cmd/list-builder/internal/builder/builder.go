package builder

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"ads-httpproxy/cmd/list-builder/config"
	"ads-httpproxy/pkg/logging"

	"go.uber.org/zap"
)

// ListManager manages multiple composite lists
type ListManager struct {
	cfg    config.BuilderConfig
	lists  map[string][]string // name -> aggregated lines
	mu     sync.RWMutex
	client *http.Client
}

// NewListManager creates a new manager
func NewListManager(cfg config.BuilderConfig) *ListManager {
	return &ListManager{
		cfg:    cfg,
		lists:  make(map[string][]string),
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

// Start starts the background refresh loop
func (m *ListManager) Start(ctx context.Context) {
	// Initial build
	m.BuildAll()

	ticker := time.NewTicker(m.cfg.RefreshInterval)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				m.BuildAll()
			}
		}
	}()
}

// BuildAll rebuilds all configured lists
func (m *ListManager) BuildAll() {
	var wg sync.WaitGroup
	for _, listCfg := range m.cfg.Lists {
		wg.Add(1)
		go func(cfg config.ListConfig) {
			defer wg.Done()
			result, err := m.buildList(cfg)
			if err != nil {
				logging.Logger.Error("Failed to build list", zap.String("name", cfg.Name), zap.Error(err))
				return
			}

			m.mu.Lock()
			m.lists[cfg.Name] = result
			m.mu.Unlock()
			logging.Logger.Info("Built list", zap.String("name", cfg.Name), zap.Int("entries", len(result)))
		}(listCfg)
	}
	wg.Wait()
}

// buildList fetches and aggregates a single list
func (m *ListManager) buildList(cfg config.ListConfig) ([]string, error) {
	uniqueEntries := make(map[string]struct{})

	for _, source := range cfg.Sources {
		var lines []string
		var err error

		if strings.HasPrefix(source, "http://") || strings.HasPrefix(source, "https://") {
			lines, err = m.fetchURL(source)
		} else {
			lines, err = m.readFile(source)
		}

		if err != nil {
			logging.Logger.Warn("Failed to fetch source", zap.String("source", source), zap.Error(err))
			continue
		}

		for _, line := range lines {
			// Basic sanitization
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			// Remove comments inline
			if idx := strings.Index(line, "#"); idx != -1 {
				line = strings.TrimSpace(line[:idx])
			}

			// Validate based on type
			if cfg.Type == "ip" || cfg.Type == "cidr" {
				if _, _, err := net.ParseCIDR(line); err != nil {
					if net.ParseIP(line) == nil {
						continue // Invalid IP/CIDR
					}
				}
			}

			uniqueEntries[line] = struct{}{}
		}
	}

	result := make([]string, 0, len(uniqueEntries))
	for entry := range uniqueEntries {
		result = append(result, entry)
	}
	return result, nil
}

func (m *ListManager) fetchURL(url string) ([]string, error) {
	resp, err := m.client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bad status: %d", resp.StatusCode)
	}

	var lines []string
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

func (m *ListManager) readFile(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

// GetList returns the current list content
func (m *ListManager) GetList(name string) ([]string, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	list, ok := m.lists[name]
	return list, ok
}
