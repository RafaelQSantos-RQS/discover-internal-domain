// Package core provides the UI-agnostic DNS enumeration logic.
// It writes results to a centralized state.Store and knows nothing about the TUI.
package core

import (
	"sync"
	"time"
)

const (
	maxNegCache = 100_000 // Max entries in negative cache
)

// NegCache is a thread-safe negative DNS cache with LRU eviction.
type NegCache struct {
	mu         sync.RWMutex
	cache      map[string]time.Time
	access     []string // LRU tracking (oldest first)
	maxEntries int
	ttl        time.Duration
}

// NewNegCache creates a new negative cache.
func NewNegCache(ttl time.Duration) *NegCache {
	return &NegCache{
		cache:      make(map[string]time.Time),
		access:     make([]string, 0, maxNegCache),
		maxEntries: maxNegCache,
		ttl:        ttl,
	}
}

// IsCached returns true if the FQDN is in the cache and not expired.
func (nc *NegCache) IsCached(fqdn string) bool {
	if nc.ttl == 0 {
		return false
	}
	nc.mu.RLock()
	defer nc.mu.RUnlock()

	expire, ok := nc.cache[fqdn]
	if !ok {
		return false
	}
	return time.Now().Before(expire)
}

// Add adds an FQDN to the negative cache.
func (nc *NegCache) Add(fqdn string) {
	if nc.ttl == 0 {
		return
	}
	nc.mu.Lock()
	defer nc.mu.Unlock()

	// Evict oldest entries if at capacity
	for len(nc.cache) >= nc.maxEntries && len(nc.access) > 0 {
		oldest := nc.access[0]
		nc.access = nc.access[1:]
		delete(nc.cache, oldest)
	}

	nc.cache[fqdn] = time.Now().Add(nc.ttl)
	nc.access = append(nc.access, fqdn)
}

// Cleanup removes expired entries.
func (nc *NegCache) Cleanup() {
	if nc.ttl == 0 {
		return
	}
	nc.mu.Lock()
	defer nc.mu.Unlock()

	now := time.Now()
	newAccess := make([]string, 0, len(nc.access))
	for _, fqdn := range nc.access {
		if expire, ok := nc.cache[fqdn]; ok && now.After(expire) {
			delete(nc.cache, fqdn)
		} else {
			newAccess = append(newAccess, fqdn)
		}
	}
	nc.access = newAccess
}
