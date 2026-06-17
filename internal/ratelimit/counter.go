package ratelimit

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// CheckRateLimit implements a sliding-window counter rate limiter using Redis
// INCR + EXPIRE. Returns nil if within the limit, or an error describing
// why the request was denied (rate limit exceeded or Redis error).
//
// The counter starts at 1 on the first request and expires after the window.
// Once count exceeds max, subsequent requests are denied until the key expires.
//
// Example: 5 login attempts per 15 minutes per username:
//
//	err := ratelimit.CheckRateLimit(ctx, rdb, "login:user:alice", 5, 15*time.Minute)
//	if err != nil {
//		http.Error(w, err.Error(), http.StatusTooManyRequests)
//		return
//	}
func CheckRateLimit(ctx context.Context, rdb *redis.Client, key string, max int, window time.Duration) error {
	if rdb == nil {
		return fmt.Errorf("rate limiter not available")
	}

	count, err := rdb.Incr(ctx, key).Result()
	if err != nil {
		return fmt.Errorf("rate limit check failed: %w", err)
	}
	if count == 1 {
		rdb.Expire(ctx, key, window)
	}
	if int(count) > max {
		return fmt.Errorf("rate limit exceeded")
	}
	return nil
}

// ResetRateLimit deletes a rate limit counter, effectively resetting it.
// Useful for clearing counters on successful login.
func ResetRateLimit(ctx context.Context, rdb *redis.Client, keys ...string) {
	if rdb == nil {
		return
	}
	rdb.Del(ctx, keys...)
}
