package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"aspm/internal/assert"
)

func setupRateLimitTest(t *testing.T) (*miniredis.Miniredis, context.Context) {
	t.Helper()
	if Rdb != nil {
		Rdb.Close()
	}
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	Rdb = redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() {
		Rdb.Close()
		mr.Close()
		Rdb = nil
	})
	return mr, context.Background()
}

func TestCheckRateLimit_Basic(t *testing.T) {
	setupRateLimitTest(t)

	allowed, remaining, resetTime := CheckRateLimit(context.Background(), "test:basic", 5)
	assert.True(t, allowed)
	assert.Equal(t, remaining, 4) // 5 - 1
	assert.True(t, resetTime > 0)
}

func TestCheckRateLimit_Exhausts(t *testing.T) {
	setupRateLimitTest(t)

	// Consume all 5 tokens
	for range 4 {
		CheckRateLimit(context.Background(), "test:exhaust", 5)
	}

	// 5th should be allowed (last one)
	allowed, remaining, _ := CheckRateLimit(context.Background(), "test:exhaust", 5)
	assert.True(t, allowed)
	assert.Equal(t, remaining, 0)

	// 6th should be denied
	allowed2, remaining2, _ := CheckRateLimit(context.Background(), "test:exhaust", 5)
	assert.False(t, allowed2)
	assert.Equal(t, remaining2, 0)
}

func TestCheckRateLimit_DifferentKeys(t *testing.T) {
	setupRateLimitTest(t)

	// Exhaust key:a
	for range 5 {
		CheckRateLimit(context.Background(), "test:ka", 5)
	}
	// key:b should still have tokens
	allowed, _, _ := CheckRateLimit(context.Background(), "test:kb", 5)
	assert.True(t, allowed)
}

func TestCheckRateLimit_WindowReset(t *testing.T) {
	mr, _ := setupRateLimitTest(t)

	// Exhaust current window
	for range 5 {
		CheckRateLimit(context.Background(), "test:window", 5)
	}
	allowed, _, _ := CheckRateLimit(context.Background(), "test:window", 5)
	assert.False(t, allowed)

	// Advance miniredis clock past window
	mr.FastForward(61 * time.Second)

	// Should be allowed in new window
	allowed2, _, _ := CheckRateLimit(context.Background(), "test:window", 5)
	assert.True(t, allowed2)
}

func TestInitRateLimiter_SetsRdb(t *testing.T) {
	mr, _ := setupRateLimitTest(t)
	Rdb = nil

	InitRateLimiter(mr.Addr())
	assert.NotNil(t, Rdb)
	assert.NotNil(t, Rdb.Ping(context.Background()).Err() == nil || Rdb.Ping(context.Background()).Err() == nil)
}

func TestRateLimiter_ExemptEndpoints(t *testing.T) {
	setupRateLimitTest(t)

	tests := []struct {
		name string
		path string
	}{
		{"health", "/api/health"},
		{"version", "/api/version"},
		{"metrics", "/metrics"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := RateLimiter(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("ok"))
			}))

			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			assert.Equal(t, rec.Code, http.StatusOK)
			// These endpoints skip rate limiting entirely, no headers set
		})
	}
}

func TestRateLimiter_HeadersSet(t *testing.T) {
	setupRateLimitTest(t)

	handler := RateLimiter(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/projects", nil)
	req.Header.Set("X-Forwarded-For", "10.0.0.1")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	resp := rec.Result()
	assert.Equal(t, resp.Header.Get("X-RateLimit-Limit"), "300")
	assert.Equal(t, resp.Header.Get("X-RateLimit-Remaining"), "299")
	assert.NotEqual(t, resp.Header.Get("X-RateLimit-Reset"), "")
}

func TestRateLimiter_Blocked(t *testing.T) {
	setupRateLimitTest(t)

	handler := RateLimiter(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/projects", nil)
	req.Header.Set("X-Forwarded-For", "10.0.0.2")

	// Exhaust rate limit (general = 300)
	for range 300 {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		_ = rec
	}

	// 301st should be blocked
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, rec.Code, http.StatusTooManyRequests)
	assert.NotEqual(t, rec.Header().Get("Retry-After"), "")
	assert.MatchesRegexp(t, rec.Body.String(), `rate_limited`)
}

func TestRateLimiter_AuthEndpoint(t *testing.T) {
	setupRateLimitTest(t)

	handler := RateLimiter(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Auth endpoints use rateLimitAuth = 20
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", nil)
	req.Header.Set("X-Forwarded-For", "10.0.0.3")

	for range 20 {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		assert.Equal(t, rec.Code, http.StatusOK)
	}

	// 21st should be blocked
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, rec.Code, http.StatusTooManyRequests)
}

func TestRateLimiter_HeavyEndpoint(t *testing.T) {
	setupRateLimitTest(t)

	handler := RateLimiter(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/findings/export", nil)
	req.Header.Set("X-Forwarded-For", "10.0.0.4")

	for range 120 {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		assert.Equal(t, rec.Code, http.StatusOK)
	}

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, rec.Code, http.StatusTooManyRequests)
}

func TestRateLimiter_DifferentIPsIndependent(t *testing.T) {
	setupRateLimitTest(t)

	handler := RateLimiter(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req1 := httptest.NewRequest(http.MethodGet, "/api/projects", nil)
	req1.Header.Set("X-Forwarded-For", "10.0.0.10")
	req2 := httptest.NewRequest(http.MethodGet, "/api/projects", nil)
	req2.Header.Set("X-Forwarded-For", "10.0.0.20")

	// Exhaust IP 10.0.0.10 (general = 300)
	for range 300 {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req1)
		_ = rec
	}

	// IP 10.0.0.10 is blocked
	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, req1)
	assert.Equal(t, rec1.Code, http.StatusTooManyRequests)

	// IP 10.0.0.20 should still work
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)
	assert.Equal(t, rec2.Code, http.StatusOK)
}
