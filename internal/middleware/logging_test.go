package middleware

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5/middleware"

	"aspm/internal/assert"
)

func captureLogs(t *testing.T, fn func()) string {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)
	t.Cleanup(func() { slog.SetDefault(prev) })
	fn()
	return buf.String()
}

func TestRequestLogger_LogsMethodAndPath(t *testing.T) {
	logs := captureLogs(t, func() {
		handler := RequestLogger(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("ok"))
		}))

		req := httptest.NewRequest(http.MethodGet, "/api/health", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
	})

	assert.MatchesRegexp(t, logs, `method=GET`)
	assert.MatchesRegexp(t, logs, `path=/api/health`)
	assert.MatchesRegexp(t, logs, `status=200`)
	assert.MatchesRegexp(t, logs, `bytes=`)
	assert.MatchesRegexp(t, logs, `latency_ms=`)
	assert.MatchesRegexp(t, logs, `remote_addr=`)
}

func TestRequestLogger_POST(t *testing.T) {
	logs := captureLogs(t, func() {
		handler := RequestLogger(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte(`{"id":"1"}`))
		}))

		req := httptest.NewRequest(http.MethodPost, "/api/projects", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
	})

	assert.MatchesRegexp(t, logs, `method=POST`)
	assert.MatchesRegexp(t, logs, `status=201`)
	assert.MatchesRegexp(t, logs, `bytes=`)
}

func TestRequestLogger_RequestID(t *testing.T) {
	logs := captureLogs(t, func() {
		handler := middleware.RequestID(RequestLogger(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})))

		req := httptest.NewRequest(http.MethodGet, "/api/health", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
	})

	// Request ID should be present in logs when chi's RequestID middleware is installed
	assert.MatchesRegexp(t, logs, `request_id=`)
}

func TestRequestLogger_WithoutRequestID(t *testing.T) {
	logs := captureLogs(t, func() {
		handler := RequestLogger(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		// Add a request ID to context manually to avoid empty
		ctx := context.WithValue(req.Context(), middleware.RequestIDKey, "")
		req = req.WithContext(ctx)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
	})

	// Should not panic when RequestID is empty
	assert.MatchesRegexp(t, logs, `request_id=`)
}
