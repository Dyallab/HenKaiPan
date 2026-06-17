package middleware

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"aspm/internal/auth"
	"github.com/redis/go-redis/v9"
)

const (
	RateLimitWindow   = 60  // 1 minute window
	rateLimitGeneral  = 300 // 300 requests per minute (5/sec)
	rateLimitAuth     = 20  // 20 requests per minute for auth endpoints
	rateLimitHeavy    = 120 // 120 requests per minute for heavy endpoints
	TokenRateLimit    = 60  // 60 requests per minute for API token auth
)

var Rdb *redis.Client
var rateLimitFailClosed = true
var trustedProxyCIDRs []*net.IPNet

// InitRateLimiter initializes the Redis client for rate limiting
func InitRateLimiter(addr string) {
	Rdb = redis.NewClient(&redis.Options{
		Addr: addr,
	})
}

// SetTrustedProxies configures CIDR ranges for trusted reverse proxies.
// X-Forwarded-For and X-Real-IP headers are only trusted when the direct
// connection comes from one of these CIDRs. If no proxies are configured,
// the first IP from X-Forwarded-For is used (backward-compatible default).
func SetTrustedProxies(cidrs []string) error {
	for _, c := range cidrs {
		_, cidr, err := net.ParseCIDR(c)
		if err != nil {
			return fmt.Errorf("invalid trusted proxy CIDR %q: %w", c, err)
		}
		trustedProxyCIDRs = append(trustedProxyCIDRs, cidr)
	}
	return nil
}

func isTrustedProxy(ip net.IP) bool {
	for _, cidr := range trustedProxyCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

func extractRemoteAddr(addr string) string {
	if idx := strings.LastIndexByte(addr, ':'); idx != -1 {
		return addr[:idx]
	}
	return addr
}

// Close closes the Redis connection
func Close() {
	if Rdb != nil {
		Rdb.Close()
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

		allowed, remaining, resetTime := CheckRateLimit(r.Context(), key, limit)

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

// CheckRateLimit checks if the request is within rate limits
// Returns: allowed, remaining, resetTime
// Fails closed (blocks request) on Redis errors for security
func CheckRateLimit(ctx context.Context, key string, limit int) (bool, int, int64) {
	now := time.Now()
	windowStart := now.Unix() / RateLimitWindow
	windowKey := fmt.Sprintf("%s:%d", key, windowStart)

	pipe := Rdb.Pipeline()
	incr := pipe.Incr(ctx, windowKey)
	pipe.Expire(ctx, windowKey, time.Duration(RateLimitWindow)*time.Second)
	_, err := pipe.Exec(ctx)

	if err != nil {
		slog.ErrorContext(ctx, "redis rate limit error - failing closed", "err", err)
		if rateLimitFailClosed {
			return false, 0, now.Add(time.Duration(RateLimitWindow) * time.Second).Unix()
		}
		return true, limit, now.Add(time.Duration(RateLimitWindow) * time.Second).Unix()
	}

	count := int(incr.Val())
	resetTime := (windowStart + 1) * RateLimitWindow

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

// ClientIP extracts the real client IP from the request, respecting trusted proxies.
// If trusted proxies are configured, X-Forwarded-For and X-Real-IP are only accepted
// when the direct connection comes from a trusted proxy. Otherwise, falls back to RemoteAddr.
// If no trusted proxies are configured, the first IP from X-Forwarded-For is used
// (backward-compatible with existing deployments behind reverse proxies).
func ClientIP(r *http.Request) string {
	directIP := net.ParseIP(extractRemoteAddr(r.RemoteAddr))

	if len(trustedProxyCIDRs) > 0 && directIP != nil && !isTrustedProxy(directIP) {
		// Connection is not from a trusted proxy — ignore proxy headers
		if directIP != nil {
			return directIP.String()
		}
		return r.RemoteAddr
	}

	// Check X-Forwarded-For header (trusted proxy or no proxies configured)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.IndexByte(xff, ','); i != -1 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}

	if directIP != nil {
		return directIP.String()
	}
	return r.RemoteAddr
}

// getClientIP extracts the client IP from the request
func getClientIP(r *http.Request) string {
	return ClientIP(r)
}

// getUserID extracts user ID from JWT claims in request context (if authenticated)
func getUserID(r *http.Request) string {
	claims := auth.GetClaims(r)
	if claims != nil && claims.UserID != "" {
		return claims.UserID
	}
	return ""
}
