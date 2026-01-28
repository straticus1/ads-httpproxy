package dnscache

import (
	"context"
	"fmt"
	"sync"
	"time"

	pb "github.com/dnsscience/dnsscienced/api/grpc/proto/pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// Client is a wrapper around the gRPC CacheService client
type Client struct {
	conn   *grpc.ClientConn
	client pb.CacheServiceClient
	mu     sync.RWMutex
	target string
}

// NewClient creates a new DNS cache client
func NewClient(target string) (*Client, error) {
	// For MVP, we use insecure credentials (internal traffic)
	// Phase 2/3 should add TLS support
	conn, err := grpc.NewClient(target, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to dnsscienced: %w", err)
	}

	return &Client{
		conn:   conn,
		client: pb.NewCacheServiceClient(conn),
		target: target,
	}, nil
}

// Close closes the gRPC connection
func (c *Client) Close() error {
	return c.conn.Close()
}

// CheckThreat performs a quick lookup for threat intelligence
func (c *Client) CheckThreat(ctx context.Context, domain string) (*pb.CacheEntry, error) {
	// Short timeout for latency sensitivity in proxy path
	ctx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()

	resp, err := c.client.Lookup(ctx, &pb.CacheLookupRequest{
		Name: domain,
		Type: "A", // Default to A logic for basic threat check
	})
	if err != nil {
		return nil, err
	}

	if len(resp.Entries) > 0 {
		return resp.Entries[0], nil
	}
	return nil, nil // Not found (or no threat data yet)
}

// Watch subscribes to the threat intelligence stream
func (c *Client) Watch(ctx context.Context) (<-chan *pb.CacheEvent, error) {
	stream, err := c.client.WatchCache(ctx, &pb.WatchCacheRequest{})
	if err != nil {
		return nil, err
	}

	ch := make(chan *pb.CacheEvent, 100)
	go func() {
		defer close(ch)
		for {
			event, err := stream.Recv()
			if err != nil {
				// Stream ended or error
				return
			}
			select {
			case ch <- event:
			case <-ctx.Done():
				return
			}
		}
	}()
	return ch, nil
}
