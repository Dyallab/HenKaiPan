// Package ratelimit provides a Redis-backed token bucket rate limiter.
//
// A token bucket has a capacity (max burst) and refills at a fixed rate
// (tokens per second). Each request consumes one token. If the bucket
// is empty, the request is denied.
//
// The implementation uses an atomic Lua script for correctness under
// concurrent access.
package ratelimit

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

// allowScript is an atomic Lua script that implements the token bucket
// algorithm. It returns [allow, tokens] where allow is 1 if the request
// was permitted, and tokens is the remaining token count after consumption.
//
// KEYS[1]  = bucket key
// ARGV[1]  = capacity (float)
// ARGV[2]  = refill rate (tokens/sec, float)
// ARGV[3]  = now (unix epoch seconds, float)
// ARGV[4]  = cost (integer, typically 1)
var allowScript = redis.NewScript(`
local key       = KEYS[1]
local capacity  = tonumber(ARGV[1])
local rate      = tonumber(ARGV[2])
local now       = tonumber(ARGV[3])
local cost      = tonumber(ARGV[4])

local bucket = redis.call("HMGET", key, "tokens", "last_refill")
local tokens       = tonumber(bucket[1])
local last_refill  = tonumber(bucket[2])

if tokens == nil then
	-- Fresh bucket: start full, consume cost immediately.
	tokens = capacity - cost
	redis.call("HMSET", key, "tokens", tokens, "last_refill", now)
	redis.call("PEXPIRE", key, math.ceil(capacity / rate) * 2000)
	return {1, tokens}
end

-- Refill based on elapsed time.
local elapsed = now - last_refill
if elapsed > 0 then
	tokens = tokens + elapsed * rate
	if tokens > capacity then
		tokens = capacity
	end
end

if tokens >= cost then
	tokens = tokens - cost
	redis.call("HMSET", key, "tokens", tokens, "last_refill", now)
	redis.call("PEXPIRE", key, math.ceil(capacity / rate) * 2000)
	return {1, tokens}
end

-- Not enough tokens: return remaining without consuming.
return {0, tokens}
`)

// TokenBucket implements the token bucket rate limiting algorithm
// backed by Redis. Safe for concurrent use.
type TokenBucket struct {
	rdb       *redis.Client
	capacity  float64
	refillRate float64 // tokens per second
	script    *redis.Script
}

// New creates a TokenBucket with the given capacity (max burst) and
// refill rate in tokens per second.
//
// Example:
//
//	// 60 requests burst, refills 1/sec
//	bucket := ratelimit.NewTokenBucket(rdb, 60, 1.0)
func NewTokenBucket(rdb *redis.Client, capacity int, refillRate float64) *TokenBucket {
	return &TokenBucket{
		rdb:        rdb,
		capacity:   float64(capacity),
		refillRate: refillRate,
		script:     allowScript,
	}
}

// Allow checks whether a request identified by key should be permitted.
// It consumes one token if allowed.
//
// Returns (allowed, remaining) where remaining is an estimate of tokens
// left in the bucket after this request.
// Capacity returns the maximum burst size of the bucket.
func (b *TokenBucket) Capacity() int {
	return int(b.capacity)
}

func (b *TokenBucket) Allow(ctx context.Context, key string) (bool, float64) {
	return b.AllowN(ctx, key, 1)
}

// AllowN checks whether n tokens can be consumed from the bucket identified
// by key. Returns (allowed, remaining).
//
// For most rate-limiting use cases, Allow (n=1) is sufficient.
func (b *TokenBucket) AllowN(ctx context.Context, key string, n int) (bool, float64) {
	if n < 0 {
		panic("ratelimit: negative AllowN cost")
	}
	if n == 0 {
		return true, 0
	}

	now := float64(time.Now().Unix())
	result, err := b.script.Run(ctx, b.rdb, []string{key},
		b.capacity, b.refillRate, now, n,
	).Int64Slice()

	if err != nil || len(result) < 2 {
		// Redis error — fail closed (deny) for security.
		return false, 0
	}

	return result[0] == 1, float64(result[1])
}
