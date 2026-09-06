//go:build integration

package smoke

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"aspm/internal/assert"
)

// reqKey performs a request with extra headers (e.g. X-API-Key,
// MCP-Protocol-Version) and returns the response for explicit status
// assertions. The caller must close resp.Body.
func reqKey(t testing.TB, c *Client, method, path string, body any, headers map[string]string) *http.Response {
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
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := c.HTTP.Do(req)
	assert.NoError(t, err)
	return resp
}

// TestExternalAndMCP covers the CI/CD surface: mint an API key via JWT,
// trigger an external scan (exercising standalone auto-create), poll its
// status, run an MCP initialize, and prove the SSRF guards (MCP method
// check + webhook localhost block). Exactly one login.
func TestExternalAndMCP(t *testing.T) {
	c := NewClient()
	c.login(t, adminUser(), adminPass())

	suffix := time.Now().UnixNano()

	// ── Mint API key ──
	var token struct {
		Token string `json:"token"`
		ID    string `json:"id"`
	}
	c.do(t, http.MethodPost, "/api/v1/tokens", map[string]string{
		"name": fmt.Sprintf("smoke-%d", suffix),
	}, &token)
	assert.True(t, token.Token != "")
	keyHeaders := map[string]string{"X-API-Key": token.Token}

	// ── External scan with auto-created standalone project ──
	extBody := map[string]any{
		"project_name": fmt.Sprintf("smoke-ext-%d", suffix),
		"repo_url":     "https://github.com/example/smoke-ext",
		"scanners":     []string{"semgrep"},
	}
	resp := reqKey(t, c, http.MethodPost, "/api/v1/scans/external", extBody, keyHeaders)
	defer resp.Body.Close()
	assert.Equal(t, resp.StatusCode, http.StatusAccepted)
	var ext struct {
		ScanIDs []string `json:"scan_ids"`
		BatchID string   `json:"batch_id"`
		Status  string   `json:"status"`
	}
	assert.NoError(t, json.NewDecoder(resp.Body).Decode(&ext))
	assert.Equal(t, ext.Status, "accepted")
	assert.True(t, len(ext.ScanIDs) > 0)

	// ── Poll external status (no strict pending assertion) ──
	stResp := reqKey(t, c, http.MethodGet, "/api/v1/scans/"+ext.ScanIDs[0]+"/status", nil, keyHeaders)
	defer stResp.Body.Close()
	assert.Equal(t, stResp.StatusCode, http.StatusOK)

	// ── MCP initialize ──
	mcpHeaders := map[string]string{
		"X-API-Key":            token.Token,
		"MCP-Protocol-Version": "2026-07-28",
	}
	initBody := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
		"params": map[string]any{
			"protocolVersion": "2026-07-28",
			"capabilities":    map[string]any{},
			"clientInfo":      map[string]string{"name": "smoke", "version": "1.0"},
		},
	}
	mcpResp := reqKey(t, c, http.MethodPost, "/v1/mcp", initBody, mcpHeaders)
	mcpBytes, _ := io.ReadAll(mcpResp.Body)
	mcpResp.Body.Close()
	assert.Equal(t, mcpResp.StatusCode, http.StatusOK)
	assert.True(t, strings.Contains(string(mcpBytes), "result"))

	// ── MCP rejects GET ──
	getResp := reqKey(t, c, http.MethodGet, "/v1/mcp", nil, keyHeaders)
	getResp.Body.Close()
	assert.Equal(t, getResp.StatusCode, http.StatusMethodNotAllowed)

	// ── MCP without API key ──
	noKeyResp := reqKey(t, c, http.MethodPost, "/v1/mcp", initBody, map[string]string{
		"MCP-Protocol-Version": "2026-07-28",
	})
	noKeyResp.Body.Close()
	assert.Equal(t, noKeyResp.StatusCode, http.StatusUnauthorized)

	// ── Webhook SSRF block (admin JWT, localhost target) ──
	ssrfResp := c.req(t, http.MethodPost, "/api/webhooks", map[string]any{
		"label": fmt.Sprintf("smoke-ssrf-%d", suffix),
		"url":   "http://127.0.0.1:9/hook",
		"events": []string{
			"scan.completed",
		},
	})
	defer ssrfResp.Body.Close()
	assert.Equal(t, ssrfResp.StatusCode, http.StatusBadRequest)
}
