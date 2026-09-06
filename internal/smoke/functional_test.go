//go:build integration

package smoke

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"aspm/internal/assert"
)

// TestFunctionalFlow exercises the core JWT journey against the live API:
// login → apps → projects → scans → findings → patch → notifications.
// It performs exactly one login to stay clear of the login rate limits
// (5/user + 10/IP per 15min; success resets both counters).
func TestFunctionalFlow(t *testing.T) {
	c := NewClient()
	c.login(t, adminUser(), adminPass())

	suffix := time.Now().UnixNano()

	// ── Apps ──
	var app struct {
		ID string `json:"id"`
	}
	c.do(t, http.MethodPost, "/api/apps", map[string]string{
		"name":        fmt.Sprintf("smoke-app-%d", suffix),
		"description": "smoke test app",
	}, &app)
	assert.True(t, app.ID != "")

	// ── Projects (app-scoped via ?app_id=) ──
	var project struct {
		ID string `json:"id"`
	}
	c.do(t, http.MethodPost, "/api/apps/"+app.ID+"/projects", map[string]string{
		"name":     fmt.Sprintf("smoke-proj-%d", suffix),
		"repo_url": "https://github.com/example/demo-api",
	}, &project)
	assert.True(t, project.ID != "")
	_ = project

	// Standalone project creation is covered by the external-scan leg
	// (external_test.go auto-creates one); here we stay app-scoped.

	// ── Scans ──
	var created struct {
		IDs []string `json:"ids"`
	}
	c.do(t, http.MethodPost, "/api/scans", map[string]string{
		"target":     "https://github.com/example/demo-api",
		"scanner":    "semgrep",
		"project_id": project.ID,
	}, &created)
	assert.True(t, len(created.IDs) > 0)
	scanID := created.IDs[0]

	// ── Poll until the worker moves the scan out of pending ──
	// Accept completed OR failed: the local worker has no external network,
	// so the clone of the example repo is expected to fail with an error.
	scanStatus := ""
	deadline := time.Now().Add(90 * time.Second)
	for {
		var scan struct {
			Status string `json:"status"`
		}
		c.get(t, "/api/scans/"+scanID, &scan)
		scanStatus = scan.Status
		if scanStatus != "" && scanStatus != "pending" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("scan %s still pending after 90s", scanID)
		}
		time.Sleep(2 * time.Second)
	}
	assert.True(t, scanStatus == "completed" || scanStatus == "failed")

	// ── Scan findings (200 with an array; may be empty if the scan failed) ──
	var scanFindings []map[string]any
	c.get(t, "/api/scans/"+scanID+"/findings", &scanFindings)

	// ── Pick a finding to PATCH: prefer one from this scan, else any ──
	findingID := ""
	originalStatus := ""
	if len(scanFindings) > 0 {
		findingID, _ = scanFindings[0]["id"].(string)
		originalStatus, _ = scanFindings[0]["status"].(string)
	}
	if findingID == "" {
		var listed struct {
			Findings []map[string]any `json:"findings"`
			Total    int              `json:"total"`
		}
		c.get(t, "/api/findings?limit=50", &listed)
		assert.True(t, len(listed.Findings) > 0)
		findingID, _ = listed.Findings[0]["id"].(string)
		originalStatus, _ = listed.Findings[0]["status"].(string)
	}
	assert.True(t, findingID != "")

	// ── PATCH status → in_review, verify, restore original ──
	var updated struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	}
	c.do(t, http.MethodPatch, "/api/findings/"+findingID, map[string]string{
		"status": "in_review",
	}, &updated)
	assert.Equal(t, updated.Status, "in_review")

	var refetched struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	}
	c.get(t, "/api/findings/"+findingID, &refetched)
	assert.Equal(t, refetched.Status, "in_review")

	if originalStatus != "" && originalStatus != "in_review" {
		var restored struct {
			Status string `json:"status"`
		}
		c.do(t, http.MethodPatch, "/api/findings/"+findingID, map[string]string{
			"status": originalStatus,
		}, &restored)
		assert.Equal(t, restored.Status, originalStatus)
	}

	// ── Notifications ──
	var notifs struct {
		Notifications []map[string]any `json:"notifications"`
		Total         int              `json:"total"`
	}
	c.get(t, "/api/notifications?limit=20", &notifs)

	var before struct {
		Count int `json:"count"`
	}
	c.get(t, "/api/notifications/unread-count", &before)

	unreadID := ""
	for _, n := range notifs.Notifications {
		if read, _ := n["read"].(bool); !read {
			unreadID, _ = n["id"].(string)
			break
		}
	}
	if unreadID != "" {
		var marked map[string]string
		c.do(t, http.MethodPatch, "/api/notifications/"+unreadID+"/read", nil, &marked)
		var after struct {
			Count int `json:"count"`
		}
		c.get(t, "/api/notifications/unread-count", &after)
		assert.Equal(t, after.Count, before.Count-1)
	}
}
