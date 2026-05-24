package icap

import (
	"errors"
	"net/http"
	"sync"
	"time"

	"ads-httpproxy/pkg/logging"
	"go.uber.org/zap"
)

// Cluster represents a load-balanced cluster of ICAP clients.
type Cluster struct {
	clients    []*Client
	mu         sync.RWMutex
	rrIndex    uint64
	stopChan   chan struct{}
}

// NewCluster creates a cluster of ICAP clients.
func NewCluster(urls []string) *Cluster {
	var clients []*Client
	for _, u := range urls {
		if u == "" {
			continue
		}
		c := NewClient(u)
		clients = append(clients, c)
	}

	cluster := &Cluster{
		clients:  clients,
		stopChan: make(chan struct{}),
	}
	
	if len(clients) > 0 {
		cluster.StartHealthChecks()
	}

	return cluster
}

// StartHealthChecks starts a periodic background go-routine to ping OPTIONS on all clients.
func (c *Cluster) StartHealthChecks() {
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-c.stopChan:
				return
			case <-ticker.C:
				c.mu.RLock()
				// Run in parallel for quick results
				var wg sync.WaitGroup
				for _, client := range c.clients {
					wg.Add(1)
					go func(cl *Client) {
						defer wg.Done()
						if err := cl.fetchOptions(); err != nil {
							logging.Logger.Debug("ICAP cluster node health check failed", zap.String("url", cl.ServerURL), zap.Error(err))
							cl.SetHealthy(false)
						} else {
							cl.SetHealthy(true)
						}
					}(client)
				}
				wg.Wait()
				c.mu.RUnlock()
			}
		}
	}()
}

// getNextClient returns the next healthy ICAP client using round-robin.
func (c *Cluster) getNextClient() (*Client, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if len(c.clients) == 0 {
		return nil, errors.New("no ICAP servers configured")
	}

	// Try all clients up to len times to find a healthy one
	for i := 0; i < len(c.clients); i++ {
		c.rrIndex++
		idx := c.rrIndex % uint64(len(c.clients))
		if c.clients[idx].IsHealthy() {
			return c.clients[idx], nil
		}
	}

	return nil, errors.New("no healthy ICAP servers available")
}

// ReqMod dispatches REQMOD to the next available healthy client.
func (c *Cluster) ReqMod(req *http.Request) (*http.Request, error) {
	// Attempt failover up to 2 times across the cluster
	maxAttempts := 2
	if len(c.clients) < 2 {
		maxAttempts = 1
	}

	for attempt := 0; attempt < maxAttempts; attempt++ {
		client, err := c.getNextClient()
		if err != nil {
			return nil, err
		}

		modReq, reqErr := client.ReqMod(req)
		if reqErr != nil {
			logging.Logger.Warn("ICAP ReqMod failed on node, attempting failover", zap.String("url", client.ServerURL), zap.Error(reqErr))
			client.SetHealthy(false) // Temporarily mark as unhealthy
			continue
		}
		return modReq, nil
	}

	return nil, errors.New("ICAP ReqMod failed on all attempts in cluster")
}

// RespMod dispatches RESPMOD to the next available healthy client.
func (c *Cluster) RespMod(resp *http.Response) (*http.Response, error) {
	maxAttempts := 2
	if len(c.clients) < 2 {
		maxAttempts = 1
	}

	for attempt := 0; attempt < maxAttempts; attempt++ {
		client, err := c.getNextClient()
		if err != nil {
			return nil, err
		}

		modResp, respErr := client.RespMod(resp)
		if respErr != nil {
			logging.Logger.Warn("ICAP RespMod failed on node, attempting failover", zap.String("url", client.ServerURL), zap.Error(respErr))
			client.SetHealthy(false)
			continue
		}
		return modResp, nil
	}

	return nil, errors.New("ICAP RespMod failed on all attempts in cluster")
}

// Close shuts down the cluster and all clients.
func (c *Cluster) Close() error {
	close(c.stopChan)
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, client := range c.clients {
		client.Close()
	}
	return nil
}
