package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"aspm/internal/assert"
)

func TestSecurityHeaders_Secure(t *testing.T) {
	handler := SecurityHeaders(true)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	resp := rec.Result()

	assert.Equal(t, resp.Header.Get("X-Content-Type-Options"), "nosniff")
	assert.Equal(t, resp.Header.Get("X-Frame-Options"), "DENY")
	assert.Equal(t, resp.Header.Get("X-XSS-Protection"), "1; mode=block")
	assert.Equal(t, resp.Header.Get("Strict-Transport-Security"), "max-age=31536000; includeSubDomains")

	csp := resp.Header.Get("Content-Security-Policy")
	assert.NotEqual(t, csp, "")
	assert.MatchesRegexp(t, csp, "default-src 'self'")
}

func TestSecurityHeaders_NotSecure(t *testing.T) {
	handler := SecurityHeaders(false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	resp := rec.Result()

	assert.Equal(t, resp.Header.Get("X-Content-Type-Options"), "nosniff")
	assert.Equal(t, resp.Header.Get("X-Frame-Options"), "DENY")
	assert.Equal(t, resp.Header.Get("Strict-Transport-Security"), "")
}

func TestSecurityHeaders_NextHandlerCalled(t *testing.T) {
	var called bool
	handler := SecurityHeaders(false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.Write([]byte("ok"))
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.True(t, called)
	assert.Equal(t, rec.Body.String(), "ok")
}

func TestSecurityHeaders_HeadersSetBeforeNext(t *testing.T) {
	handler := SecurityHeaders(true)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Headers should already be set when next handler runs
		h := w.Header().Get("X-Content-Type-Options")
		assert.Equal(t, h, "nosniff")
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
}
