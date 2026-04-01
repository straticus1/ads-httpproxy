package cache

import (
	"container/list"
	"sync"
	"time"
)

// MemoryCache implements an in-memory LRU cache
type MemoryCache struct {
	maxSize  int64 // Maximum size in bytes
	maxTTL   time.Duration
	mu       sync.RWMutex
	items    map[string]*cacheItem
	lru      *list.List
	size     int64
	evictions uint64
}

// cacheItem represents a cached entry
type cacheItem struct {
	key       string
	value     []byte
	expiresAt time.Time
	size      int64
	element   *list.Element
}

// NewMemoryCache creates a new in-memory LRU cache
func NewMemoryCache(maxSizeMB int, maxTTL time.Duration) *MemoryCache {
	return &MemoryCache{
		maxSize: int64(maxSizeMB) * 1024 * 1024, // Convert MB to bytes
		maxTTL:  maxTTL,
		items:   make(map[string]*cacheItem),
		lru:     list.New(),
	}
}

// Get retrieves a value from cache
func (mc *MemoryCache) Get(key string) ([]byte, bool) {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	item, ok := mc.items[key]
	if !ok {
		return nil, false
	}

	// Check expiration
	if time.Now().After(item.expiresAt) {
		mc.deleteItem(item)
		return nil, false
	}

	// Move to front (most recently used)
	mc.lru.MoveToFront(item.element)

	return item.value, true
}

// Set stores a value in cache
func (mc *MemoryCache) Set(key string, value []byte, ttl time.Duration) {
	if ttl > mc.maxTTL {
		ttl = mc.maxTTL
	}

	mc.mu.Lock()
	defer mc.mu.Unlock()

	size := int64(len(value))

	// Remove existing item if present
	if existing, ok := mc.items[key]; ok {
		mc.deleteItem(existing)
	}

	// Evict items if necessary
	for mc.size+size > mc.maxSize && mc.lru.Len() > 0 {
		mc.evictOldest()
	}

	// Create new item
	item := &cacheItem{
		key:       key,
		value:     value,
		expiresAt: time.Now().Add(ttl),
		size:      size,
	}

	// Add to front of LRU list
	item.element = mc.lru.PushFront(item)
	mc.items[key] = item
	mc.size += size
}

// Delete removes a value from cache
func (mc *MemoryCache) Delete(key string) {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	if item, ok := mc.items[key]; ok {
		mc.deleteItem(item)
	}
}

// Clear removes all items from cache
func (mc *MemoryCache) Clear() {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	mc.items = make(map[string]*cacheItem)
	mc.lru = list.New()
	mc.size = 0
}

// Len returns number of items in cache
func (mc *MemoryCache) Len() int {
	mc.mu.RLock()
	defer mc.mu.RUnlock()
	return len(mc.items)
}

// Size returns total size of cached data in bytes
func (mc *MemoryCache) Size() int64 {
	mc.mu.RLock()
	defer mc.mu.RUnlock()
	return mc.size
}

// Evictions returns number of evictions
func (mc *MemoryCache) Evictions() uint64 {
	mc.mu.RLock()
	defer mc.mu.RUnlock()
	return mc.evictions
}

// CleanupExpired removes expired entries
func (mc *MemoryCache) CleanupExpired() int {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	now := time.Now()
	count := 0

	// Iterate from back (least recently used)
	for element := mc.lru.Back(); element != nil; {
		item := element.Value.(*cacheItem)
		next := element.Prev()

		if now.After(item.expiresAt) {
			mc.deleteItem(item)
			count++
		}

		element = next
	}

	return count
}

// StartCleanup starts periodic cleanup of expired entries
func (mc *MemoryCache) StartCleanup(interval time.Duration) chan struct{} {
	stopChan := make(chan struct{})

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				mc.CleanupExpired()
			case <-stopChan:
				return
			}
		}
	}()

	return stopChan
}

// Internal methods

func (mc *MemoryCache) deleteItem(item *cacheItem) {
	if item.element != nil {
		mc.lru.Remove(item.element)
	}
	delete(mc.items, item.key)
	mc.size -= item.size
}

func (mc *MemoryCache) evictOldest() {
	element := mc.lru.Back()
	if element == nil {
		return
	}

	item := element.Value.(*cacheItem)
	mc.deleteItem(item)
	mc.evictions++
}
