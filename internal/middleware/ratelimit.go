package middleware

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"aspm/internal/auth"
	"github.com/redis/go-redis/v9"
)

const (
	rateLimitWindow   = 60  // 1 minute window
	rateLimitGeneral  = 300 // 300 requests per minute (5/sec)
	rateLimitAuth     = 20  // 20 requests per minute for auth endpoints
	rateLimitHeavy    = 120 // 120 requests per minute for heavy endpoints
)

var rdb *redis.Client
var rateLimitFailClosed = true

// InitRateLimiter initializes the Redis client for rate limiting
func InitRateLimiter(addr string) {
	rdb = redis.NewClient(&redis.Options{
		Addr: addr,
	})
}

// Close closes the Redis connection
func Close() {
	if rdb != nil {
		rdb.Close()
	}
}

// RateLimiter middleware - applies rate limiting based on endpoint type
func RateLimiter(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := getClientIP(r)
		if ip == "" {
			ip = "unknown"
		}

		// Determine rate limit based on path
		var limit int
		var key string

		switch {
		case isAuthEndpoint(r.URL.Path):
			limit = rateLimitAuth
			key = fmt.Sprintf("ratelimit:auth:%s", ip)
		case isHeavyEndpoint(r.URL.Path):
			// For heavy endpoints, also consider user ID if available
			userID := getUserID(r)
			if userID != "" {
				key = fmt.Sprintf("ratelimit:heavy:%s", userID)
			} else {
				key = fmt.Sprintf("ratelimit:heavy:%s", ip)
			}
			limit = rateLimitHeavy
		default:
			key = fmt.Sprintf("ratelimit:general:%s", ip)
			limit = rateLimitGeneral
		}

		// Skip rate limiting for health and metrics endpoints
		if r.URL.Path == "/api/health" || r.URL.Path == "/api/version" || r.URL.Path == "/metrics" {
			next.ServeHTTP(w, r)
			return
		}

		allowed, remaining, resetTime := checkRateLimit(r.Context(), key, limit)

		// Set rate limit headers
		w.Header().Set("X-RateLimit-Limit", strconv.Itoa(limit))
		w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(remaining))
		w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(resetTime, 10))

		if !allowed {
			w.Header().Set("Retry-After", strconv.Itoa(int(resetTime-time.Now().Unix())))
			w.Header().Set("Content-Type", "application/json")
			slog.WarnContext(r.Context(), "rate limit exceeded", "ip", ip, "path", r.URL.Path, "limit", limit)
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte(`{"code":"rate_limited","message":"Too many requests. Please try again later."}`))
			return
		}

		next.ServeHTTP(w, r)
	})
}

// checkRateLimit checks if the request is within rate limits
// Returns: allowed, remaining, resetTime
// Fails closed (blocks request) on Redis errors for security
func checkRateLimit(ctx context.Context, key string, limit int) (bool, int, int64) {
	now := time.Now()
	windowStart := now.Unix() / rateLimitWindow
	windowKey := fmt.Sprintf("%s:%d", key, windowStart)

	pipe := rdb.Pipeline()
	incr := pipe.Incr(ctx, windowKey)
	pipe.Expire(ctx, windowKey, time.Duration(rateLimitWindow)*time.Second)
	_, err := pipe.Exec(ctx)

	if err != nil {
		slog.ErrorContext(ctx, "redis rate limit error - failing closed", "err", err)
		if rateLimitFailClosed {
			return false, 0, now.Add(time.Duration(rateLimitWindow) * time.Second).Unix()
		}
		return true, limit, now.Add(time.Duration(rateLimitWindow) * time.Second).Unix()
	}

	count := int(incr.Val())
	resetTime := (windowStart + 1) * rateLimitWindow

	if count > limit {
		return false, 0, resetTime
	}

	return true, limit - count, resetTime
}

// isAuthEndpoint checks if the path is an authentication endpoint
func isAuthEndpoint(path string) bool {
	return path == "/api/auth/login" || path == "/api/auth/logout"
}

// isHeavyEndpoint checks if the path is a resource-heavy endpoint
func isHeavyEndpoint(path string) bool {
	return path == "/api/findings/export" ||
		path == "/api/metrics/trends" ||
		path == "/api/metrics/risk"
}

// getClientIP extracts the client IP from the request
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header first (for proxied requests)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return xff
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to RemoteAddr
	return r.RemoteAddr
}

// getUserID extracts user ID from JWT claims in request context (if authenticated)
func getUserID(r *http.Request) string {
	claims := auth.GetClaims(r)
	if claims != nil && claims.UserID != "" {
		return claims.UserID
	}
	return ""
}
