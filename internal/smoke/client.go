//go:build integration

// Package smoke exercises a live HenKaiPan API over HTTP. Every file in the
// package carries the `integration` build tag so the default `make test-race`
// run (`go test -race ./internal/...`) ignores it; run it explicitly with
// `go test -race -count=1 -tags=integration ./internal/smoke/`.
//
// The suite targets SMOKE_API_URL (default http://localhost:8080) and skips
// itself in TestMain when the API is unreachable, so it degrades gracefully
// on machines without the stack running.
package smoke

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"aspm/internal/assert"
)

// apiURL returns the base URL of the live API under test.
func apiURL() string {
	if u := os.Getenv("SMOKE_API_URL"); u != "" {
		return strings.TrimRight(u, "/")
	}
	return "http://localhost:8080"
}

// Client is a thin HTTP client for smoke tests. It keeps a cookie jar so a
// successful login authenticates every subsequent request.
type Client struct {
	BaseURL string
	HTTP    *http.Client
}

// NewClient builds a smoke Client pointed at SMOKE_API_URL with a cookie jar.
func NewClient() *Client {
	return &Client{
		BaseURL: apiURL(),
		HTTP: &http.Client{
			Jar:     &jar{},
			Timeout: 10 * time.Second,
		},
	}
}

// login performs POST /api/auth/login and asserts a 200 response plus the
// aspm_token cookie in the client's jar.
func (c *Client) login(t testing.TB, username, password string) {
	t.Helper()
	resp := c.req(t, http.MethodPost, "/api/auth/login", map[string]string{
		"username": username,
		"password": password,
	})
	defer resp.Body.Close()
	assert.Equal(t, resp.StatusCode, http.StatusOK)
	assert.True(t, c.hasCookie("aspm_token"))
}

// req performs a request against the live API and returns the response.
// The caller must close resp.Body. A non-nil body is JSON-encoded.
func (c *Client) req(t testing.TB, method, path string, body any) *http.Response {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		assert.NoError(t, err)
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.BaseURL+path, rdr)
	assert.NoError(t, err)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.HTTP.Do(req)
	assert.NoError(t, err)
	return resp
}

// do performs a request, asserts a 2xx status, and decodes the JSON body
// into out (when out is non-nil).
func (c *Client) do(t testing.TB, method, path string, body any, out any) {
	t.Helper()
	resp := c.req(t, method, path, body)
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("%s %s: unexpected status %d: %s", method, path, resp.StatusCode, strings.TrimSpace(string(b)))
	}
	if out != nil {
		assert.NoError(t, json.NewDecoder(resp.Body).Decode(out))
	}
}

// get is a convenience wrapper for do with GET and no request body.
func (c *Client) get(t testing.TB, path string, out any) {
	t.Helper()
	c.do(t, http.MethodGet, path, nil, out)
}

// hasCookie reports whether the jar holds a cookie with the given name for
// the client's base URL.
func (c *Client) hasCookie(name string) bool {
	u, err := url.Parse(c.BaseURL)
	if err != nil {
		return false
	}
	for _, ck := range c.HTTP.Jar.Cookies(u) {
		if ck.Name == name {
			return true
		}
	}
	return false
}

// jar is a minimal http.CookieJar that stores cookies per host and ignores
// the Secure flag. The local API sets Secure=true on aspm_token even when
// served over plain HTTP (COOKIE_SECURE=true in .env), and the standard
// library jar refuses to send Secure cookies over http:// — which would
// break every authenticated leg. Smoke tests run against localhost, so
// Secure is irrelevant here.
type jar struct {
	mu      sync.Mutex
	cookies map[string][]*http.Cookie
}

func (j *jar) SetCookies(u *url.URL, cookies []*http.Cookie) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.cookies == nil {
		j.cookies = make(map[string][]*http.Cookie)
	}
	j.cookies[u.Host] = cookies
}

func (j *jar) Cookies(u *url.URL) []*http.Cookie {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.cookies[u.Host]
}