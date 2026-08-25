package handlers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"aspm/internal/assert"
	"aspm/internal/datascope"
	"aspm/internal/models"
	"aspm/internal/repository"
)

// ── Test fixtures ──────────────────────────────────────────────────────────

type mcpReqBuilder struct {
	method string
	id     any
	hasID  bool
	name   string // params.name (tools/call)
	args   map[string]any
	metaPV string // _meta protocol version; "" omits _meta
}

func (b mcpReqBuilder) body() string {
	params := map[string]any{}
	if b.name != "" {
		params["name"] = b.name
	}
	if b.args != nil {
		params["arguments"] = b.args
	}
	if b.metaPV != "" {
		params["_meta"] = map[string]any{"io.modelcontextprotocol/protocolVersion": b.metaPV}
	}
	msg := map[string]any{"jsonrpc": "2.0", "method": b.method, "params": params}
	if b.hasID {
		msg["id"] = b.id
	}
	out, _ := json.Marshal(msg)
	return string(out)
}

// validReq is a well-formed modern request for the given method.
func validReq(method string) mcpReqBuilder {
	return mcpReqBuilder{method: method, id: 1, hasID: true, metaPV: "2026-07-28"}
}

func newMCPHandler() *Handler { return &Handler{} }

func doMCP(t *testing.T, h *Handler, body string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	ctx := context.WithValue(req.Context(), tokenCtxKey, &repository.Token{ID: "tok-1"})
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()
	h.HandleMCP(rec, req)
	return rec
}

func decodeResp(t *testing.T, rec *httptest.ResponseRecorder) *jsonRPCResponse {
	t.Helper()
	var resp jsonRPCResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v (body=%q)", err, rec.Body.String())
	}
	return &resp
}

func resultMap(t *testing.T, raw json.RawMessage) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	return m
}

// assertMapKey type-asserts m[key] to T and compares it to want. Needed because
// the generic assert.Equal can't unify a typed literal against the any-typed map value.
func assertMapKey[T any](t *testing.T, m map[string]any, key string, want T) {
	t.Helper()
	got, ok := m[key].(T)
	if !ok {
		t.Fatalf("key %q: got %T (%v), want %T", key, m[key], m[key], want)
	}
	assert.Equal(t, got, want)
}

type mockMetricsRepo struct {
	repository.MetricsRepository
	summary *models.MetricsSummary
	err     error
}

func (m *mockMetricsRepo) Summary(_ context.Context, _ datascope.Scope) (*models.MetricsSummary, error) {
	if m.err != nil {
		return nil, m.err
	}
	if m.summary == nil {
		return &models.MetricsSummary{FindingsBySeverity: map[string]int{"critical": 2, "high": 5}}, nil
	}
	return m.summary, nil
}

// ── server/discover ────────────────────────────────────────────────────────

func TestMCP_Discover(t *testing.T) {
	h := newMCPHandler()
	rec := doMCP(t, h, validReq("server/discover").body(), map[string]string{
		"MCP-Protocol-Version": "2026-07-28",
		"Mcp-Method":          "server/discover",
	})

	assert.Equal(t, rec.Code, http.StatusOK)
	resp := decodeResp(t, rec)
	res := resultMap(t, resp.Result)

	assert.Equal(t, res["resultType"], "complete")
	assertMapKey[[]any](t, res, "supportedVersions", []any{"2026-07-28"})
	assert.NotNil(t, res["capabilities"])
	assert.NotNil(t, res["_meta"])
	assert.Equal(t, res["cacheScope"], "public")
	assertMapKey[float64](t, res, "ttlMs", float64(3600000))
}

// ── Protocol version negotiation ───────────────────────────────────────────

func TestMCP_MissingProtocolVersionHeader(t *testing.T) {
	h := newMCPHandler()
	rec := doMCP(t, h, validReq("tools/list").body(), map[string]string{
		"Mcp-Method": "tools/list",
	})

	assert.Equal(t, rec.Code, http.StatusBadRequest)
	resp := decodeResp(t, rec)
	assert.NotNil(t, resp.Error)
	assert.Equal(t, resp.Error.Code, -32020) // HeaderMismatch
}

func TestMCP_HeaderBodyVersionMismatch(t *testing.T) {
	h := newMCPHandler()
	b := validReq("tools/list")
	b.metaPV = "2025-03-26" // body says one thing, header another
	rec := doMCP(t, h, b.body(), map[string]string{
		"MCP-Protocol-Version": "2026-07-28",
		"Mcp-Method":           "tools/list",
	})

	assert.Equal(t, rec.Code, http.StatusBadRequest)
	resp := decodeResp(t, rec)
	assert.Equal(t, resp.Error.Code, -32020) // HeaderMismatch
}

func TestMCP_UnsupportedVersion(t *testing.T) {
	h := newMCPHandler()
	b := validReq("tools/list")
	b.metaPV = "2025-03-26" // header and body agree, but unsupported
	rec := doMCP(t, h, b.body(), map[string]string{
		"MCP-Protocol-Version": "2025-03-26",
		"Mcp-Method":           "tools/list",
	})

	assert.Equal(t, rec.Code, http.StatusBadRequest)
	resp := decodeResp(t, rec)
	assert.Equal(t, resp.Error.Code, -32022) // UnsupportedProtocolVersionError
	data, ok := resp.Error.Data.(map[string]any)
	assert.True(t, ok)
	assertMapKey[[]any](t, data, "supported", []any{"2026-07-28"})
	assert.Equal(t, data["requested"], "2025-03-26")
}

// ── Standard request headers (Mcp-Method, Mcp-Name) ───────────────────────

func TestMCP_MissingMcpMethod(t *testing.T) {
	h := newMCPHandler()
	rec := doMCP(t, h, validReq("tools/list").body(), map[string]string{
		"MCP-Protocol-Version": "2026-07-28",
	})

	assert.Equal(t, rec.Code, http.StatusBadRequest)
	assert.Equal(t, decodeResp(t, rec).Error.Code, -32020)
}

func TestMCP_McpMethodMismatch(t *testing.T) {
	h := newMCPHandler()
	rec := doMCP(t, h, validReq("tools/list").body(), map[string]string{
		"MCP-Protocol-Version": "2026-07-28",
		"Mcp-Method":           "tools/call", // does not match body method
	})

	assert.Equal(t, rec.Code, http.StatusBadRequest)
	assert.Equal(t, decodeResp(t, rec).Error.Code, -32020)
}

func TestMCP_ToolsCallMissingMcpName(t *testing.T) {
	h := newMCPHandler()
	b := validReq("tools/call")
	b.name = "get_dashboard_summary"
	rec := doMCP(t, h, b.body(), map[string]string{
		"MCP-Protocol-Version": "2026-07-28",
		"Mcp-Method":           "tools/call",
	})

	assert.Equal(t, rec.Code, http.StatusBadRequest)
	assert.Equal(t, decodeResp(t, rec).Error.Code, -32020)
}

func TestMCP_ToolsCallMcpNameMismatch(t *testing.T) {
	h := newMCPHandler()
	b := validReq("tools/call")
	b.name = "get_dashboard_summary"
	rec := doMCP(t, h, b.body(), map[string]string{
		"MCP-Protocol-Version": "2026-07-28",
		"Mcp-Method":           "tools/call",
		"Mcp-Name":             "list_projects", // mismatch
	})

	assert.Equal(t, rec.Code, http.StatusBadRequest)
	assert.Equal(t, decodeResp(t, rec).Error.Code, -32020)
}

func TestMCP_ToolsCallMcpNameBase64Sentinel(t *testing.T) {
	h := &Handler{store: repository.Stores{Metrics: &mockMetricsRepo{}}}
	b := validReq("tools/call")
	b.name = "get_dashboard_summary"
	b.args = map[string]any{}
	sentinel := "=?base64?" + base64.StdEncoding.EncodeToString([]byte("get_dashboard_summary")) + "?="
	rec := doMCP(t, h, b.body(), map[string]string{
		"MCP-Protocol-Version": "2026-07-28",
		"Mcp-Method":           "tools/call",
		"Mcp-Name":             sentinel,
	})

	assert.Equal(t, rec.Code, http.StatusOK)
	resp := decodeResp(t, rec)
	res := resultMap(t, resp.Result)
	content, ok := res["content"].([]any)
	assert.True(t, ok)
	assert.True(t, len(content) >= 1)
	assert.Equal(t, res["resultType"], "complete")
	assert.NotNil(t, res["_meta"])
}

// ── Origin guard ──────────────────────────────────────────────────────────

func TestMCP_InvalidOrigin(t *testing.T) {
	h := newMCPHandler()
	h.allowedOrigins = []string{"https://allowed.example"}
	rec := doMCP(t, h, validReq("server/discover").body(), map[string]string{
		"MCP-Protocol-Version": "2026-07-28",
		"Mcp-Method":           "server/discover",
		"Origin":               "https://evil.example",
	})

	assert.Equal(t, rec.Code, http.StatusForbidden)
}

func TestMCP_AbsentOriginAllowed(t *testing.T) {
	h := newMCPHandler()
	h.allowedOrigins = []string{"https://allowed.example"}
	// No Origin header — desktop clients typically omit it.
	rec := doMCP(t, h, validReq("server/discover").body(), map[string]string{
		"MCP-Protocol-Version": "2026-07-28",
		"Mcp-Method":           "server/discover",
	})

	assert.Equal(t, rec.Code, http.StatusOK)
}

// ── tools/list + no session header ─────────────────────────────────────────

func TestMCP_ToolsList(t *testing.T) {
	h := newMCPHandler()
	rec := doMCP(t, h, validReq("tools/list").body(), map[string]string{
		"MCP-Protocol-Version": "2026-07-28",
		"Mcp-Method":           "tools/list",
	})

	assert.Equal(t, rec.Code, http.StatusOK)
	resp := decodeResp(t, rec)
	res := resultMap(t, resp.Result)
	tools, ok := res["tools"].([]any)
	assert.True(t, ok)
	assert.Equal(t, len(tools), 7)
	assert.Equal(t, res["resultType"], "complete")
	assertMapKey[float64](t, res, "ttlMs", float64(3600000))
	// Stateless: no session id is ever minted.
	assert.Equal(t, rec.Header().Get("MCP-Session-Id"), "")
}

// ── tools/call happy path ──────────────────────────────────────────────────

func TestMCP_ToolsCallDashboardSummary(t *testing.T) {
	h := &Handler{store: repository.Stores{Metrics: &mockMetricsRepo{}}}
	b := validReq("tools/call")
	b.name = "get_dashboard_summary"
	b.args = map[string]any{}
	rec := doMCP(t, h, b.body(), map[string]string{
		"MCP-Protocol-Version": "2026-07-28",
		"Mcp-Method":           "tools/call",
		"Mcp-Name":             "get_dashboard_summary",
	})

	assert.Equal(t, rec.Code, http.StatusOK)
	resp := decodeResp(t, rec)
	res := resultMap(t, resp.Result)
	content, ok := res["content"].([]any)
	assert.True(t, ok)
	assert.True(t, len(content) >= 1)
	assert.Equal(t, res["resultType"], "complete")
	assert.NotNil(t, res["_meta"])
}

// ── Unknown method → 404 ───────────────────────────────────────────────────

func TestMCP_UnknownMethod(t *testing.T) {
	h := newMCPHandler()
	rec := doMCP(t, h, validReq("foo/bar").body(), map[string]string{
		"MCP-Protocol-Version": "2026-07-28",
		"Mcp-Method":           "foo/bar",
	})

	assert.Equal(t, rec.Code, http.StatusNotFound)
	resp := decodeResp(t, rec)
	assert.Equal(t, resp.Error.Code, -32601) // Method not found
}

// ── Notification → 202 ─────────────────────────────────────────────────────

func TestMCP_NotificationAccepted(t *testing.T) {
	h := newMCPHandler()
	b := validReq("notifications/initialized")
	b.hasID = false // notifications carry no id
	rec := doMCP(t, h, b.body(), nil)

	assert.Equal(t, rec.Code, http.StatusAccepted)
	assert.Equal(t, rec.Body.Len(), 0)
}

// ── Legacy initialize → friendly reject ────────────────────────────────────

func TestMCP_LegacyInitializeRejected(t *testing.T) {
	h := newMCPHandler()
	// Legacy clients send initialize without modern headers/_meta.
	body := `{"jsonrpc":"2.0","id":1,"method":"initialize"}`
	rec := doMCP(t, h, body, nil)

	assert.Equal(t, rec.Code, http.StatusBadRequest)
	resp := decodeResp(t, rec)
	assert.Equal(t, resp.Error.Code, -32022) // UnsupportedProtocolVersionError
	data, ok := resp.Error.Data.(map[string]any)
	assert.True(t, ok)
	assertMapKey[[]any](t, data, "supported", []any{"2026-07-28"})
}
