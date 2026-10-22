package shared

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"
)

const (
	defaultMemoryCacheTTL      = 10 * time.Minute // Cache items for 10 minutes
	memoryCacheCleanupInterval = 2 * time.Minute  // Cleanup every 2 minutes
	maxMemoryCacheSize         = 1000             // Maximum cache entries
	preloadThreshold           = 1 * time.Minute  // Preload when TTL is under this
)

// MemoryCache provides caching with preloading
type MemoryCache struct {
	cache          map[string]*MemoryCacheEntry
	loader         CacheLoader
	mu             sync.RWMutex
	ttl            time.Duration
	cleanupTicker  *time.Ticker
	preloadTicker  *time.Ticker
	stopChan       chan struct{}
	isRunning      bool
	preloadEnabled bool
}

// MemoryCacheEntry represents a cached item with metadata
type MemoryCacheEntry struct {
	Key        string
	data       any // Keep data private for encapsulation
	CreatedAt  time.Time
	ExpiresAt  time.Time
	LastUsedAt time.Time
	HitCount   int64
	isLoading  bool
	loadError  error
}

// CacheLoader defines the interface for loading cache data
type CacheLoader interface {
	Load(ctx context.Context, key string) (any, error)
	ShouldPreload(key string, entry *MemoryCacheEntry) bool
}

// SmartMemoryCacheConfig holds configuration for the memory cache
type SmartMemoryCacheConfig struct {
	TTL             time.Duration
	CleanupInterval time.Duration
	MaxSize         int
	PreloadEnabled  bool
	Loader          CacheLoader
}

// NewSmartMemoryCache creates a new smart memory cache
func NewSmartMemoryCache(config *SmartMemoryCacheConfig) *MemoryCache {
	if config == nil {
		config = &SmartMemoryCacheConfig{
			TTL:             defaultMemoryCacheTTL,
			CleanupInterval: memoryCacheCleanupInterval,
			MaxSize:         maxMemoryCacheSize,
			PreloadEnabled:  true,
		}
	}

	if config.TTL == 0 {
		config.TTL = defaultMemoryCacheTTL
	}
	if config.CleanupInterval == 0 {
		config.CleanupInterval = memoryCacheCleanupInterval
	}
	if config.MaxSize == 0 {
		config.MaxSize = maxMemoryCacheSize
	}

	return &MemoryCache{
		cache:          make(map[string]*MemoryCacheEntry),
		loader:         config.Loader,
		ttl:            config.TTL,
		stopChan:       make(chan struct{}),
		preloadEnabled: config.PreloadEnabled,
	}
}

// Start begins cache management routines
func (smc *MemoryCache) Start(ctx context.Context) error {
	smc.mu.Lock()
	defer smc.mu.Unlock()

	if smc.isRunning {
		return fmt.Errorf("smart memory cache is already running")
	}

	log.Printf("[MemoryCache] Starting smart memory cache (TTL: %v, Preload: %v)",
		smc.ttl, smc.preloadEnabled)

	// Start cleanup routine
	smc.cleanupTicker = time.NewTicker(memoryCacheCleanupInterval)
	smc.isRunning = true

	go smc.cleanupRoutine(ctx)

	// Start preload routine if enabled
	if smc.preloadEnabled && smc.loader != nil {
		smc.preloadTicker = time.NewTicker(30 * time.Second) // Preload check every 30s
		go smc.preloadRoutine(ctx)
	}

	return nil
}

// Get retrieves an item from cache or loads it if missing
func (smc *MemoryCache) Get(ctx context.Context, key string) (any, error) {
	// Try to get from cache first
	smc.mu.RLock()
	if entry, exists := smc.cache[key]; exists && !smc.isExpired(entry) {
		// Cache hit
		entry.HitCount++
		entry.LastUsedAt = time.Now()
		smc.mu.RUnlock()

		log.Printf("[MemoryCache] Cache hit for key: %s (hit count: %d)", key, entry.HitCount)
		return entry.data, nil
	}
	smc.mu.RUnlock()

	log.Printf("[MemoryCache] Cache miss for key: %s", key)

	return smc.loadAndStore(ctx, key)
}

// Put stores an item in the cache
func (smc *MemoryCache) Put(key string, data any) {
	smc.mu.Lock()
	defer smc.mu.Unlock()

	now := time.Now()
	entry := &MemoryCacheEntry{
		Key:        key,
		data:       data,
		CreatedAt:  now,
		ExpiresAt:  now.Add(smc.ttl),
		LastUsedAt: now,
		HitCount:   1,
	}

	// Check if we need to evict entries
	if len(smc.cache) >= maxMemoryCacheSize {
		smc.evictLRUEntry()
	}

	smc.cache[key] = entry
	log.Printf("[MemoryCache] Stored item in cache: %s", key)
}

// Delete removes an item from the cache
func (smc *MemoryCache) Delete(key string) {
	smc.mu.Lock()
	defer smc.mu.Unlock()

	if _, exists := smc.cache[key]; exists {
		delete(smc.cache, key)
		log.Printf("[MemoryCache] Deleted item from cache: %s", key)
	}
}

// Clear removes all items from the cache
func (smc *MemoryCache) Clear() {
	smc.mu.Lock()
	defer smc.mu.Unlock()

	count := len(smc.cache)
	smc.cache = make(map[string]*MemoryCacheEntry)
	log.Printf("[MemoryCache] Cleared cache (%d entries)", count)
}

// Shutdown stops the cache and cleanup routines
func (smc *MemoryCache) Shutdown(ctx context.Context) error {
	smc.mu.Lock()
	defer smc.mu.Unlock()

	if !smc.isRunning {
		return nil
	}

	log.Printf("[MemoryCache] Shutting down smart memory cache")

	// Stop routines
	close(smc.stopChan)
	if smc.cleanupTicker != nil {
		smc.cleanupTicker.Stop()
	}
	if smc.preloadTicker != nil {
		smc.preloadTicker.Stop()
	}

	// Clear cache
	count := len(smc.cache)
	smc.cache = make(map[string]*MemoryCacheEntry)
	smc.isRunning = false

	log.Printf("[MemoryCache] Cache shutdown completed (%d entries cleared)", count)
	return nil
}

// Contains checks if a key exists in the cache
func (smc *MemoryCache) Contains(key string) bool {
	smc.mu.RLock()
	defer smc.mu.RUnlock()

	entry, exists := smc.cache[key]
	return exists && !smc.isExpired(entry)
}

// Size returns the current cache size
func (smc *MemoryCache) Size() int {
	smc.mu.RLock()
	defer smc.mu.RUnlock()
	return len(smc.cache)
}

// GetCacheInfo returns information about a cached item
func (smc *MemoryCache) GetCacheInfo(key string) map[string]any {
	smc.mu.RLock()
	defer smc.mu.RUnlock()

	if entry, exists := smc.cache[key]; exists {
		return map[string]any{
			"exists":       true,
			"created_at":   entry.CreatedAt,
			"expires_at":   entry.ExpiresAt,
			"last_used_at": entry.LastUsedAt,
			"hit_count":    entry.HitCount,
			"is_expired":   smc.isExpired(entry),
			"is_loading":   entry.isLoading,
			"has_error":    entry.loadError != nil,
		}
	}

	return map[string]any{
		"exists": false,
	}
}

// Private methods

func (smc *MemoryCache) loadAndStore(ctx context.Context, key string) (any, error) {
	if smc.loader == nil {
		return nil, fmt.Errorf("no loader configured for cache")
	}

	// Check if already loading (prevent duplicate loads)
	smc.mu.Lock()
	if entry, exists := smc.cache[key]; exists && entry.isLoading {
		smc.mu.Unlock()
		// Wait a bit and try again
		time.Sleep(10 * time.Millisecond)
		return smc.Get(ctx, key)
	}

	// Mark as loading
	now := time.Now()
	loadingEntry := &MemoryCacheEntry{
		Key:        key,
		CreatedAt:  now,
		ExpiresAt:  now.Add(smc.ttl),
		LastUsedAt: now,
		isLoading:  true,
	}
	smc.cache[key] = loadingEntry
	smc.mu.Unlock()

	// Load data
	log.Printf("[MemoryCache] Loading data for key: %s", key)

	data, err := smc.loader.Load(ctx, key)
	if err != nil {

		// Update entry with error
		smc.mu.Lock()
		if entry, exists := smc.cache[key]; exists {
			entry.isLoading = false
			entry.loadError = err
		}
		smc.mu.Unlock()

		log.Printf("[MemoryCache] Failed to load data for key %s: %v", key, err)
		return nil, fmt.Errorf("failed to load data for key %s: %v", key, err)
	}

	// Store loaded data
	smc.mu.Lock()
	entry := &MemoryCacheEntry{
		Key:        key,
		data:       data,
		CreatedAt:  now,
		ExpiresAt:  now.Add(smc.ttl),
		LastUsedAt: now,
		HitCount:   1,
		isLoading:  false,
	}

	// Check if we need to evict entries
	if len(smc.cache) >= maxMemoryCacheSize {
		smc.evictLRUEntry()
	}

	smc.cache[key] = entry
	smc.mu.Unlock()

	log.Printf("[MemoryCache] Successfully loaded and cached data for key: %s", key)
	return data, nil
}

func (smc *MemoryCache) isExpired(entry *MemoryCacheEntry) bool {
	return time.Now().After(entry.ExpiresAt)
}

func (smc *MemoryCache) evictLRUEntry() {
	if len(smc.cache) == 0 {
		return
	}

	var lruKey string
	var lruTime time.Time
	isFirst := true

	// Find least recently used entry
	for key, entry := range smc.cache {
		if isFirst || entry.LastUsedAt.Before(lruTime) {
			lruKey = key
			lruTime = entry.LastUsedAt
			isFirst = false
		}
	}

	if lruKey != "" {
		delete(smc.cache, lruKey)
		log.Printf("[MemoryCache] Evicted LRU entry: %s", lruKey)
	}
}

func (smc *MemoryCache) cleanupRoutine(ctx context.Context) {
	defer log.Printf("[MemoryCache] Cleanup routine stopped")

	for {
		select {
		case <-smc.cleanupTicker.C:
			smc.performCleanup()
		case <-smc.stopChan:
			return
		case <-ctx.Done():
			return
		}
	}
}

func (smc *MemoryCache) performCleanup() {
	smc.mu.Lock()
	defer smc.mu.Unlock()

	expiredKeys := make([]string, 0)

	// Find expired entries
	for key, entry := range smc.cache {
		if smc.isExpired(entry) {
			expiredKeys = append(expiredKeys, key)
		}
	}

	// Remove expired entries
	for _, key := range expiredKeys {
		delete(smc.cache, key)
	}

	if len(expiredKeys) > 0 {
		log.Printf("[MemoryCache] Cleaned up %d expired cache entries", len(expiredKeys))
	}

}

func (smc *MemoryCache) preloadRoutine(ctx context.Context) {
	defer log.Printf("[MemoryCache] Preload routine stopped")

	for {
		select {
		case <-smc.preloadTicker.C:
			smc.performPreload(ctx)
		case <-smc.stopChan:
			return
		case <-ctx.Done():
			return
		}
	}
}

func (smc *MemoryCache) performPreload(ctx context.Context) {
	if smc.loader == nil {
		return
	}

	smc.mu.RLock()
	preloadCandidates := make([]*MemoryCacheEntry, 0)

	// Find entries that need preloading
	for _, entry := range smc.cache {
		if !entry.isLoading && entry.loadError == nil {
			// Check if entry is approaching expiration
			timeToExpiry := time.Until(entry.ExpiresAt)
			if timeToExpiry < preloadThreshold {
				if smc.loader.ShouldPreload(entry.Key, entry) {
					preloadCandidates = append(preloadCandidates, entry)
				}
			}
		}
	}
	smc.mu.RUnlock()

	// Preload candidates
	for _, entry := range preloadCandidates {
		select {
		case <-ctx.Done():
			return
		default:
			smc.preloadEntry(ctx, entry)
		}
	}
}

func (smc *MemoryCache) preloadEntry(ctx context.Context, entry *MemoryCacheEntry) {
	log.Printf("[MemoryCache] Preloading entry: %s", entry.Key)

	// Load fresh data
	data, err := smc.loader.Load(ctx, entry.Key)
	if err != nil {
		log.Printf("[MemoryCache] Preload failed for key %s: %v", entry.Key, err)
		return
	}

	// Update entry with fresh data
	smc.mu.Lock()
	if cachedEntry, exists := smc.cache[entry.Key]; exists {
		now := time.Now()
		cachedEntry.data = data
		cachedEntry.ExpiresAt = now.Add(smc.ttl)
		cachedEntry.LastUsedAt = now
		cachedEntry.loadError = nil
	}
	smc.mu.Unlock()

	log.Printf("[MemoryCache] Successfully preloaded entry: %s", entry.Key)
}

// DefaultCacheLoader provides a simple implementation of CacheLoader
type DefaultCacheLoader struct {
	loadFunc func(ctx context.Context, key string) (any, error)
}

// Load implements CacheLoader interface
func (dcl *DefaultCacheLoader) Load(ctx context.Context, key string) (any, error) {
	if dcl.loadFunc == nil {
		return nil, fmt.Errorf("no load function configured")
	}
	return dcl.loadFunc(ctx, key)
}

// ShouldPreload implements CacheLoader interface
func (dcl *DefaultCacheLoader) ShouldPreload(key string, entry *MemoryCacheEntry) bool {
	// Simple strategy: preload if hit count > 1 (item has been accessed multiple times)
	return entry.HitCount > 1
}
