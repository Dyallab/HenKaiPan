package handlers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"

	"aspm/internal/datascope"
	"aspm/internal/repository"
)

// ── Stateless MCP (2026-07-28) ───────────────────────────────────────────
//
// The server speaks the modern, stateless MCP protocol (revision 2026-07-28):
// there is no initialize handshake and no server-side session state. Every
// request is self-contained, authenticated by the X-API-Key token injected by
// the APIKeyAuth middleware, and carries its protocol version in the
// MCP-Protocol-Version header plus the request body _meta.

const mcpProtocolVersion = "2026-07-28"

var mcpServerInfo = map[string]string{"name": "henkaipan-mcp", "version": "1.0.0"}

// mcpResultMeta returns the serverInfo _meta object servers SHOULD attach to
// each result under io.modelcontextprotocol/serverInfo.
func mcpResultMeta() map[string]any {
	return map[string]any{"io.modelcontextprotocol/serverInfo": mcpServerInfo}
}

// ── JSON-RPC 2.0 Types ────────────────────────────────────────────────────

type jsonRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type jsonRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *jsonRPCError   `json:"error,omitempty"`
}

type jsonRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

// ── MCP Protocol Types ────────────────────────────────────────────────────

type mcpTool struct {
	Name        string      `json:"name"`
	Description string      `json:"description"`
	InputSchema inputSchema `json:"inputSchema"`
}

type inputSchema struct {
	Type       string                    `json:"type"`
	Properties map[string]propertySchema `json:"properties"`
	Required   []string                  `json:"required,omitempty"`
}

type propertySchema struct {
	Type        string `json:"type"`
	Description string `json:"description,omitempty"`
}

// mcpParams is used to read the _meta protocol version and the tools/call tool
// name without disturbing each tool implementation's own params decode.
type mcpParams struct {
	Name string `json:"name"`
	Meta *struct {
		ProtocolVersion string `json:"io.modelcontextprotocol/protocolVersion,omitempty"`
	} `json:"_meta,omitempty"`
}

// ── MCP Handler ───────────────────────────────────────────────────────────

func (h *Handler) HandleMCP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	h.handleMCPPost(w, r)
}

func (h *Handler) handleMCPPost(w http.ResponseWriter, r *http.Request) {
	token := apiKeyFromContext(r)
	if token == nil {
		writeError(w, r, http.StatusUnauthorized, "valid API key required")
		return
	}

	// Origin guard — DNS rebinding protection. Only applies when an Origin
	// header is present (typical of browser clients); desktop LLM clients
	// usually omit it and are allowed through.
	if origin := r.Header.Get("Origin"); origin != "" && !h.originAllowed(origin) {
		writeMCPError(w, http.StatusForbidden, nil, -32020, "invalid origin", nil)
		return
	}

	var req jsonRPCRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeMCPError(w, http.StatusBadRequest, nil, -32700, "Parse error: invalid JSON-RPC", nil)
		return
	}

	// Notifications (no id) are acknowledged without per-request header
	// validation: the 2026-07-28 Streamable HTTP transport defines no
	// client-to-server notifications, so this is a lenient accept path.
	if req.ID == nil {
		w.WriteHeader(http.StatusAccepted)
		return
	}

	// Modern-only: the legacy initialize handshake is unsupported. Surface the
	// supported versions so legacy clients get an actionable diagnostic.
	if req.Method == "initialize" {
		writeMCPError(w, http.StatusBadRequest, req.ID, -32022,
			"Unsupported protocol version: initialize handshake is not supported",
			map[string]any{"supported": []string{mcpProtocolVersion}, "requested": "initialize"},
		)
		return
	}

	// Parse params once for _meta and tools/call name validation.
	var p mcpParams
	if len(req.Params) > 0 {
		_ = json.Unmarshal(req.Params, &p)
	}

	// ── Protocol version negotiation (MCP-Protocol-Version header + _meta) ──
	pvHeader := r.Header.Get("MCP-Protocol-Version")
	if pvHeader == "" {
		writeMCPError(w, http.StatusBadRequest, req.ID, -32020,
			"Missing required header: MCP-Protocol-Version", nil)
		return
	}
	pvBody := ""
	if p.Meta != nil {
		pvBody = p.Meta.ProtocolVersion
	}
	if pvBody != "" && pvBody != pvHeader {
		writeMCPError(w, http.StatusBadRequest, req.ID, -32020,
			"Header mismatch: MCP-Protocol-Version header does not match _meta protocol version", nil)
		return
	}
	if pvHeader != mcpProtocolVersion {
		writeMCPError(w, http.StatusBadRequest, req.ID, -32022,
			"Unsupported protocol version",
			map[string]any{"supported": []string{mcpProtocolVersion}, "requested": pvHeader},
		)
		return
	}

	// ── Standard request headers (Mcp-Method, Mcp-Name) ──
	mHeader := r.Header.Get("Mcp-Method")
	if mHeader == "" || mHeader != req.Method {
		writeMCPError(w, http.StatusBadRequest, req.ID, -32020,
			"Header mismatch: Mcp-Method header does not match body method", nil)
		return
	}
	if req.Method == "tools/call" {
		nHeader := r.Header.Get("Mcp-Name")
		decoded, ok := decodeMCPHeader(nHeader)
		if !ok || nHeader == "" || decoded != p.Name {
			writeMCPError(w, http.StatusBadRequest, req.ID, -32020,
				"Header mismatch: Mcp-Name header does not match params.name", nil)
			return
		}
	}

	// ── Dispatch ──
	var response *jsonRPCResponse
	switch req.Method {
	case "server/discover":
		response = h.mcpDiscover(&req)
	case "tools/list":
		response = h.mcpToolsList(&req)
	case "tools/call":
		response = h.mcpToolsCall(r.Context(), &req)
	default:
		writeMCPError(w, http.StatusNotFound, req.ID, -32601, "Method not found: "+req.Method, nil)
		return
	}

	respJSON, err := json.Marshal(response)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "failed to marshal response")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(respJSON)
}

// writeMCPError writes a JSON-RPC 2.0 error response with the given HTTP
// status. id may be nil for unparseable bodies (the spec permits error
// responses with no id).
func writeMCPError(w http.ResponseWriter, status int, id json.RawMessage, code int, message string, data any) {
	resp := jsonRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error:   &jsonRPCError{Code: code, Message: message, Data: data},
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(resp)
}

// decodeMCPHeader decodes the Base64 sentinel encoding used for Mcp-Name (and
// Mcp-Param-*) header values that are not plain ASCII. The sentinel format is
// =?base64?<Base64>?=. Returns the decoded value and true on success, or "" /
// false when a value claims to be encoded but is not valid Base64.
func decodeMCPHeader(raw string) (string, bool) {
	const prefix = "=?base64?"
	const suffix = "?="
	if strings.HasPrefix(raw, prefix) && strings.HasSuffix(raw, suffix) && len(raw) >= len(prefix)+len(suffix) {
		enc := raw[len(prefix) : len(raw)-len(suffix)]
		dec, err := base64.StdEncoding.DecodeString(enc)
		if err != nil {
			return "", false
		}
		return string(dec), true
	}
	return raw, true
}

// originAllowed reports whether the given Origin is permitted. When no allowed
// origins are configured (e.g. tests, or a "*" wildcard policy) all origins pass.
func (h *Handler) originAllowed(origin string) bool {
	if len(h.allowedOrigins) == 0 {
		return true
	}
	for _, o := range h.allowedOrigins {
		if o == "*" || o == origin {
			return true
		}
	}
	return false
}

func (h *Handler) mcpDiscover(req *jsonRPCRequest) *jsonRPCResponse {
	result, _ := json.Marshal(map[string]any{
		"resultType":       "complete",
		"supportedVersions": []string{mcpProtocolVersion},
		"capabilities":     map[string]any{"tools": map[string]any{}},
		"_meta":            mcpResultMeta(),
		"instructions":     "HenKaiPan MCP server. Use tools/list to enumerate security tools, then tools/call with the tool name and arguments. Authenticated via X-API-Key.",
		"ttlMs":            3600000,
		"cacheScope":       "public",
	})
	return &jsonRPCResponse{JSONRPC: "2.0", ID: req.ID, Result: result}
}

// ── Tools / List ──────────────────────────────────────────────────────────
//
// Keep the tool catalog below in sync with the machine-readable spec published at
// @dyallab/docs/llms/mcp-tools.json (package version 1.18.0+).

func (h *Handler) mcpToolsList(req *jsonRPCRequest) *jsonRPCResponse {
	tools := []mcpTool{
		{
			Name:        "list_projects",
			Description: "List all security projects with optional name filter or glob pattern",
			InputSchema: inputSchema{
				Type: "object",
				Properties: map[string]propertySchema{
					"filter":  {Type: "string", Description: "Optional text search across project name and URL"},
					"pattern": {Type: "string", Description: "Optional glob pattern (e.g. 'org/*', 'team-*')"},
				},
			},
		},
		{
			Name:        "create_project",
			Description: "Create a new security project for scanning",
			InputSchema: inputSchema{
				Type: "object",
				Properties: map[string]propertySchema{
					"name":           {Type: "string", Description: "Project name (required)"},
					"repo_url":       {Type: "string", Description: "Git repository URL (e.g. https://github.com/org/repo)"},
					"description":    {Type: "string", Description: "Optional project description"},
					"default_branch": {Type: "string", Description: "Default branch (default: main)"},
				},
				Required: []string{"name"},
			},
		},
		{
			Name:        "trigger_scan",
			Description: "Start a security scan on a project. Scans run security scanners against the project's codebase to find vulnerabilities.",
			InputSchema: inputSchema{
				Type: "object",
				Properties: map[string]propertySchema{
					"project_id": {Type: "string", Description: "Project UUID (required)"},
					"scanners":   {Type: "string", Description: "Comma-separated scanners or packs (required). Packs: 'all', 'sast', 'sca', 'secrets', 'iac', 'containers'. Individual: 'semgrep', 'gosec', 'trivy', 'grype', 'osv-scanner', 'gitleaks', 'trufflehog', 'checkov', 'tfsec', 'kics', 'nuclei'"},
					"branch":     {Type: "string", Description: "Optional branch to scan (defaults to repo default)"},
				},
				Required: []string{"project_id", "scanners"},
			},
		},
		{
			Name:        "get_scan_status",
			Description: "Get the status and findings of a security scan",
			InputSchema: inputSchema{
				Type: "object",
				Properties: map[string]propertySchema{
					"scan_id": {Type: "string", Description: "Scan UUID (required)"},
				},
				Required: []string{"scan_id"},
			},
		},
		{
			Name:        "query_findings",
			Description: "Search and filter security findings (vulnerabilities found by scanners)",
			InputSchema: inputSchema{
				Type: "object",
				Properties: map[string]propertySchema{
					"severity": {Type: "string", Description: "Comma-separated severity filter: critical,high,medium,low"},
					"status":   {Type: "string", Description: "Filter by status: open,in_review,fixed,accepted_risk,verified"},
					"scanner":  {Type: "string", Description: "Filter by scanner name (e.g. 'semgrep', 'trivy')"},
					"cve_id":   {Type: "string", Description: "Filter by CVE identifier"},
					"page":     {Type: "number", Description: "Page number for pagination (default: 1)"},
					"limit":    {Type: "number", Description: "Results per page (default: 50, max: 200)"},
				},
			},
		},
		{
			Name:        "get_vulnerabilities",
			Description: "List canonical vulnerabilities with cross-scanner correlation and filters",
			InputSchema: inputSchema{
				Type: "object",
				Properties: map[string]propertySchema{
					"project_id":  {Type: "string", Description: "Filter by project UUID"},
					"severity":    {Type: "string", Description: "Comma-separated severity filter: critical,high,medium,low"},
					"status":      {Type: "string", Description: "Filter by status: open,in_review,accepted_risk,fixed,verified"},
					"engine_type": {Type: "string", Description: "Filter by engine: SCA,SAST,Secrets,IaC,Containers,DAST"},
					"search":      {Type: "string", Description: "Full-text search across title and CVE ID"},
					"page":        {Type: "number", Description: "Page number (default: 1)"},
					"limit":       {Type: "number", Description: "Results per page (default: 100, max: 200)"},
				},
			},
		},
		{
			Name:        "get_dashboard_summary",
			Description: "Get high-level security metrics summary: total findings, critical/high counts, projects scanned, SLA compliance",
			InputSchema: inputSchema{
				Type:       "object",
				Properties: map[string]propertySchema{},
			},
		},
	}

	result, _ := json.Marshal(map[string]any{
		"tools":      tools,
		"resultType": "complete",
		"ttlMs":      3600000,
		"cacheScope": "public",
		"_meta":      mcpResultMeta(),
	})
	return &jsonRPCResponse{JSONRPC: "2.0", ID: req.ID, Result: result}
}

// ── Tools / Call ──────────────────────────────────────────────────────────

func (h *Handler) mcpToolsCall(ctx context.Context, req *jsonRPCRequest) *jsonRPCResponse {
	var params struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return mcpError(req, -32602, "Invalid params: could not parse tool name and arguments")
	}

	switch params.Name {
	case "list_projects":
		return h.mcpListProjects(ctx, req, params.Arguments)
	case "create_project":
		return h.mcpCreateProject(ctx, req, params.Arguments)
	case "trigger_scan":
		return h.mcpTriggerScan(ctx, req, params.Arguments)
	case "get_scan_status":
		return h.mcpGetScanStatus(ctx, req, params.Arguments)
	case "query_findings":
		return h.mcpQueryFindings(ctx, req, params.Arguments)
	case "get_vulnerabilities":
		return h.mcpGetVulnerabilities(ctx, req, params.Arguments)
	case "get_dashboard_summary":
		return h.mcpDashboardSummary(ctx, req, params.Arguments)
	default:
		return mcpError(req, -32602, "Unknown tool: "+params.Name)
	}
}

// ── Tool Implementations ──────────────────────────────────────────────────

func (h *Handler) mcpListProjects(ctx context.Context, req *jsonRPCRequest, args json.RawMessage) *jsonRPCResponse {
	var params struct {
		Filter  string `json:"filter"`
		Pattern string `json:"pattern"`
	}
	json.Unmarshal(args, &params)

	var projects any
	var err error

	if params.Pattern != "" {
		projects, err = h.store.Apps.ListStandaloneByPattern(ctx, datascope.Admin(), params.Pattern)
	} else {
		projects, err = h.store.Apps.ListAllProjects(ctx, datascope.Admin(), params.Filter)
	}
	if err != nil {
		return mcpError(req, -32603, "Failed to list projects: "+err.Error())
	}

	return &jsonRPCResponse{JSONRPC: "2.0", ID: req.ID, Result: mcpToolResult(map[string]any{"projects": projects})}
}

func (h *Handler) mcpCreateProject(ctx context.Context, req *jsonRPCRequest, args json.RawMessage) *jsonRPCResponse {
	var params struct {
		Name          string `json:"name"`
		RepoURL       string `json:"repo_url"`
		Description   string `json:"description"`
		DefaultBranch string `json:"default_branch"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return mcpError(req, -32602, "Invalid arguments: could not parse project parameters")
	}
	if params.Name == "" {
		return mcpError(req, -32602, "name is required")
	}
	if params.DefaultBranch == "" {
		params.DefaultBranch = "main"
	}

	project, err := h.store.Apps.CreateStandaloneProject(ctx, repository.ProjectCreate{
		Name:          params.Name,
		Description:   params.Description,
		RepoURL:       params.RepoURL,
		DefaultBranch: params.DefaultBranch,
	})
	if err != nil {
		return mcpError(req, -32603, "Failed to create project: "+err.Error())
	}

	return &jsonRPCResponse{JSONRPC: "2.0", ID: req.ID, Result: mcpToolResult(map[string]any{"project": project})}
}

func (h *Handler) mcpTriggerScan(ctx context.Context, req *jsonRPCRequest, args json.RawMessage) *jsonRPCResponse {
	var params struct {
		ProjectID string `json:"project_id"`
		Scanners  string `json:"scanners"`
		Branch    string `json:"branch"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return mcpError(req, -32602, "Invalid arguments: could not parse scan parameters")
	}
	if params.ProjectID == "" || params.Scanners == "" {
		return mcpError(req, -32602, "project_id and scanners are required")
	}

	scannerNames := strings.Split(params.Scanners, ",")
	for i := range scannerNames {
		scannerNames[i] = strings.TrimSpace(scannerNames[i])
	}

	resolved, err := resolveScanners(scannerNames)
	if err != nil {
		return mcpError(req, -32602, "Invalid scanner: "+err.Error())
	}

	target := params.ProjectID
	if params.Branch != "" {
		target = target + "#" + params.Branch
	}

	scanIDs, batchID, err := h.createScanRecords(ctx, target, resolved, &params.ProjectID, "")
	if err != nil {
		return mcpError(req, -32603, "Failed to trigger scan: "+err.Error())
	}

	return &jsonRPCResponse{JSONRPC: "2.0", ID: req.ID, Result: mcpToolResult(map[string]any{
		"scan_ids": scanIDs,
		"batch_id": batchID,
		"status":   "accepted",
	})}
}

func (h *Handler) mcpGetScanStatus(ctx context.Context, req *jsonRPCRequest, args json.RawMessage) *jsonRPCResponse {
	var params struct {
		ScanID string `json:"scan_id"`
	}
	if err := json.Unmarshal(args, &params); err != nil || params.ScanID == "" {
		return mcpError(req, -32602, "scan_id is required")
	}

	scan, err := h.store.Scans.Get(ctx, params.ScanID)
	if err != nil {
		return mcpError(req, -32603, "Scan not found: "+err.Error())
	}

	findings, _ := h.store.Findings.GetByScanID(ctx, params.ScanID)

	return &jsonRPCResponse{JSONRPC: "2.0", ID: req.ID, Result: mcpToolResult(map[string]any{
		"scan":     scan,
		"findings": findings,
	})}
}

func (h *Handler) mcpQueryFindings(ctx context.Context, req *jsonRPCRequest, args json.RawMessage) *jsonRPCResponse {
	var params struct {
		Severity string `json:"severity"`
		Status   string `json:"status"`
		Scanner  string `json:"scanner"`
		CVEID    string `json:"cve_id"`
		Page     int    `json:"page"`
		Limit    int    `json:"limit"`
	}
	json.Unmarshal(args, &params)
	if params.Page < 1 {
		params.Page = 1
	}
	if params.Limit < 1 || params.Limit > 200 {
		params.Limit = 50
	}

	var severities []string
	if params.Severity != "" {
		severities = strings.Split(params.Severity, ",")
	}

	findings, total, err := h.store.Findings.List(ctx, repository.FindingFilter{
		Severities: severities,
		Scanner:    params.Scanner,
		Status:     params.Status,
		CVESearch:  params.CVEID,
		Page:       params.Page,
		Limit:      params.Limit,
		UserID:     nil, // MCP uses API key auth — no user scope
	})
	if err != nil {
		return mcpError(req, -32603, "Failed to query findings: "+err.Error())
	}

	return &jsonRPCResponse{JSONRPC: "2.0", ID: req.ID, Result: mcpToolResult(map[string]any{
		"findings": findings,
		"total":    total,
		"page":     params.Page,
		"limit":    params.Limit,
	})}
}

func (h *Handler) mcpGetVulnerabilities(ctx context.Context, req *jsonRPCRequest, args json.RawMessage) *jsonRPCResponse {
	var params struct {
		ProjectID  string `json:"project_id"`
		Severity   string `json:"severity"`
		Status     string `json:"status"`
		EngineType string `json:"engine_type"`
		Search     string `json:"search"`
		Page       int    `json:"page"`
		Limit      int    `json:"limit"`
	}
	json.Unmarshal(args, &params)
	if params.Page < 1 {
		params.Page = 1
	}
	if params.Limit < 1 || params.Limit > 200 {
		params.Limit = 100
	}

	var severities []string
	if params.Severity != "" {
		severities = strings.Split(params.Severity, ",")
	}

	vulns, total, err := h.store.Vulnerabilities.List(ctx, repository.VulnerabilityFilter{
		ProjectID:  params.ProjectID,
		Severities: severities,
		EngineType: params.EngineType,
		Status:     params.Status,
		Search:     params.Search,
		Page:       params.Page,
		Limit:      params.Limit,
	})
	if err != nil {
		return mcpError(req, -32603, "Failed to list vulnerabilities: "+err.Error())
	}

	return &jsonRPCResponse{JSONRPC: "2.0", ID: req.ID, Result: mcpToolResult(map[string]any{
		"vulnerabilities": vulns,
		"total":           total,
		"page":            params.Page,
		"limit":           params.Limit,
	})}
}

func (h *Handler) mcpDashboardSummary(ctx context.Context, req *jsonRPCRequest, args json.RawMessage) *jsonRPCResponse {
	metrics, err := h.store.Metrics.Summary(ctx, datascope.Admin())
	if err != nil {
		return mcpError(req, -32603, "Failed to get dashboard summary: "+err.Error())
	}

	return &jsonRPCResponse{JSONRPC: "2.0", ID: req.ID, Result: mcpToolResult(map[string]any{"summary": metrics})}
}

// ── Helpers ───────────────────────────────────────────────────────────────

// mcpToolResult wraps tool call data in MCP-standard content format and attaches
// the modern result envelope (resultType + serverInfo _meta). The MCP protocol
// requires tools/call responses to have a "content" array with at least one
// text entry, rather than bare business data in result.
func mcpToolResult(data map[string]any) json.RawMessage {
	payload, _ := json.Marshal(data)
	wrapped, _ := json.Marshal(map[string]any{
		"content":    []map[string]any{{"type": "text", "text": string(payload)}},
		"resultType": "complete",
		"_meta":      mcpResultMeta(),
	})
	return wrapped
}

func mcpError(req *jsonRPCRequest, code int, message string) *jsonRPCResponse {
	return &jsonRPCResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Error:   &jsonRPCError{Code: code, Message: message},
	}
}
