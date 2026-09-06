//go:build integration

package smoke

import (
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"

	"aspm/internal/assert"
)

// TestMain skips the whole package when the live API is unreachable, so the
// suite degrades gracefully on machines without the stack running.
func TestMain(m *testing.M) {
	if !apiReachable() {
		fmt.Printf("smoke: API not reachable at %s — skipping integration smoke tests\n", apiURL())
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// apiReachable probes the public liveness endpoint.
func apiReachable() bool {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(apiURL() + "/api/health")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// adminUser returns ADMIN_USER from the environment, defaulting to "admin"
// (the same default EnsureAdminUser uses at startup).
func adminUser() string {
	if u := os.Getenv("ADMIN_USER"); u != "" {
		return u
	}
	return "admin"
}

// adminPass returns ADMIN_PASS from the environment, defaulting to "admin".
func adminPass() string {
	if p := os.Getenv("ADMIN_PASS"); p != "" {
		return p
	}
	return "admin"
}

// TestHealth checks the public liveness endpoint.
func TestHealth(t *testing.T) {
	c := NewClient()
	var body struct {
		Status string `json:"status"`
	}
	c.get(t, "/api/health", &body)
	// The overall status depends on live worker activity (a worker with no
	// recent jobs reports "degraded"), so accept both healthy states rather
	// than assuming runtime state beyond the seeded admin user.
	assert.True(t, body.Status == "ok" || body.Status == "degraded")
}

// TestSSOStatus checks the public SSO enablement flag.
func TestSSOStatus(t *testing.T) {
	c := NewClient()
	var body struct {
		Enabled bool `json:"enabled"`
	}
	c.get(t, "/api/auth/sso/status", &body)
}

// TestLoginWrongPassword checks that a bad credential pair is rejected with
// 401. A unique username keeps the per-user login rate limit (5/15min) from
// accumulating across runs.
func TestLoginWrongPassword(t *testing.T) {
	c := NewClient()
	username := fmt.Sprintf("smoke_wrong_%d", time.Now().UnixNano())
	resp := c.req(t, http.MethodPost, "/api/auth/login", map[string]string{
		"username": username,
		"password": "definitely-not-the-password",
	})
	defer resp.Body.Close()
	assert.Equal(t, resp.StatusCode, http.StatusUnauthorized)
}

// TestLoginAdmin checks the admin credential pair from the environment
// (ADMIN_USER/ADMIN_PASS, defaulting to admin/admin) and that the aspm_token
// cookie lands in the jar. A successful login resets the login rate-limit
// counters, so this also keeps the suite's own attempts from accumulating.
func TestLoginAdmin(t *testing.T) {
	c := NewClient()
	c.login(t, adminUser(), adminPass())
}

// TestMe checks the authenticated identity endpoint.
func TestMe(t *testing.T) {
	c := NewClient()
	c.login(t, adminUser(), adminPass())
	var body struct {
		Username string `json:"username"`
	}
	c.get(t, "/api/me", &body)
	assert.Equal(t, body.Username, adminUser())
}

// TestLimits checks the authenticated tier-limits endpoint.
func TestLimits(t *testing.T) {
	c := NewClient()
	c.login(t, adminUser(), adminPass())
	var body map[string]any
	c.get(t, "/api/limits", &body)
	assert.True(t, len(body) > 0)
}

// TestConfigStatus checks the authenticated deployment-config endpoint.
func TestConfigStatus(t *testing.T) {
	c := NewClient()
	c.login(t, adminUser(), adminPass())
	var body map[string]any
	c.get(t, "/api/config/status", &body)
	assert.True(t, len(body) > 0)
}

// TestDetailedHealth checks the authenticated per-component health endpoint.
func TestDetailedHealth(t *testing.T) {
	c := NewClient()
	c.login(t, adminUser(), adminPass())
	var body struct {
		Status string `json:"status"`
	}
	c.get(t, "/api/health/detailed", &body)
	assert.True(t, body.Status == "ok" || body.Status == "degraded")
}