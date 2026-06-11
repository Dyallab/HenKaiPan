// Package cache provides a lightweight Redis-backed caching layer
// with automatic key prefixing.
//
// Usage:
//
//	cc := cache.NewCache(rdb)
//	err := cc.Set(ctx, "mykey", "myvalue", cache.DefaultTTL)
//	val, err := cc.Get(ctx, "mykey")   // val == "" on miss
//	ok, err := cc.Exists(ctx, "mykey")
//	err := cc.Del(ctx, "mykey")
package cache

import (
	"context"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	// DefaultTTL is the default time-to-live for cache entries (5 minutes).
	DefaultTTL = 5 * time.Minute

	// keyPrefix is prepended to every key to namespace finding detail cache entries.
	keyPrefix = "cache:findings:"
)

// Cache is a lightweight Redis-backed cache.
// All keys are automatically prefixed with keyPrefix.
type Cache struct {
	rdb *redis.Client
}

// NewCache creates a new Cache backed by the given Redis client.
//
// The caller is responsible for closing the client when shutting down.
func NewCache(rdb *redis.Client) *Cache {
	return &Cache{rdb: rdb}
}

// Get retrieves the value for the given key.
// Returns ("", nil) when the key does not exist (cache miss).
func (c *Cache) Get(ctx context.Context, key string) (string, error) {
	val, err := c.rdb.Get(ctx, keyPrefix+key).Result()
	if errors.Is(err, redis.Nil) {
		return "", nil
	}
	return val, err
}

// Set stores a value under the given key with the specified TTL.
// Pass cache.DefaultTTL to use the default expiration (5 minutes).
func (c *Cache) Set(ctx context.Context, key string, value string, ttl time.Duration) error {
	return c.rdb.Set(ctx, keyPrefix+key, value, ttl).Err()
}

// Del removes the given key from the cache.
func (c *Cache) Del(ctx context.Context, key string) error {
	return c.rdb.Del(ctx, keyPrefix+key).Err()
}

// Exists reports whether the key exists in the cache.
func (c *Cache) Exists(ctx context.Context, key string) (bool, error) {
	n, err := c.rdb.Exists(ctx, keyPrefix+key).Result()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}
