package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"aspm/internal/repository"
)

// ── MCP Session Management ────────────────────────────────────────────────

const mcpMaxSessionsPerToken = 10

// mcpSession represents a single MCP client connection.
type mcpSession struct {
	id        string
	tokenID   string
	responses chan json.RawMessage
	ctx       context.Context
	cancel    context.CancelFunc
}

var (
	mcpSessions   = map[string]*mcpSession{}
	mcpSessionsMu sync.RWMutex
)

func registerMCPSession(ctx context.Context, tokenID, id string) *mcpSession {
	ctx, cancel := context.WithCancel(ctx)
	s := &mcpSession{
		id:        id,
		tokenID:   tokenID,
		responses: make(chan json.RawMessage, 100),
		ctx:       ctx,
		cancel:    cancel,
	}
	mcpSessionsMu.Lock()
	mcpSessions[id] = s
	mcpSessionsMu.Unlock()
	return s
}

func unregisterMCPSession(id string) {
	mcpSessionsMu.Lock()
	delete(mcpSessions, id)
	mcpSessionsMu.Unlock()
}

func getMCPSession(id string) *mcpSession {
	mcpSessionsMu.RLock()
	defer mcpSessionsMu.RUnlock()
	return mcpSessions[id]
}

func countMCPSessionsByToken(tokenID string) int {
	mcpSessionsMu.RLock()
	defer mcpSessionsMu.RUnlock()
	count := 0
	for _, s := range mcpSessions {
		if s.tokenID == tokenID {
			count++
		}
	}
	return count
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
}

// ── MCP Protocol Types ────────────────────────────────────────────────────

type mcpTool struct {
	Name        string      `json:"name"`
	Description string      `json:"description"`
	InputSchema inputSchema `json:"inputSchema"`
}

type inputSchema struct {
	Type       string                     `json:"type"`
	Properties map[string]propertySchema  `json:"properties"`
	Required   []string                   `json:"required,omitempty"`
}

type propertySchema struct {
	Type        string `json:"type"`
	Description string `json:"description,omitempty"`
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

	var req jsonRPCRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid JSON-RPC")
		return
	}

	if req.Method == "initialize" {
		h.handleMCPInitialize(w, r, token, &req)
		return
	}

	sessionID := r.Header.Get("MCP-Session-Id")
	if sessionID == "" {
		writeError(w, r, http.StatusBadRequest, "MCP-Session-Id header required")
		return
	}

	session := getMCPSession(sessionID)
	if session == nil || session.ctx.Err() != nil {
		writeError(w, r, http.StatusNotFound, "session not found or expired")
		return
	}

	if token.ID != session.tokenID {
		writeError(w, r, http.StatusForbidden, "this token does not own this session")
		return
	}

	response := h.processMCPRequest(session.ctx, &req)

	if req.ID == nil {
		w.WriteHeader(http.StatusAccepted)
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

func (h *Handler) handleMCPInitialize(w http.ResponseWriter, r *http.Request, token *repository.Token, req *jsonRPCRequest) {
	if countMCPSessionsByToken(token.ID) >= mcpMaxSessionsPerToken {
		writeError(w, r, http.StatusTooManyRequests, "too many MCP sessions for this token")
		return
	}

	sessionID := fmt.Sprintf("mcp_%s_%d", token.ID, time.Now().UnixNano())
	session := registerMCPSession(context.Background(), token.ID, sessionID)

	response := h.mcpInitialize(req)
	respJSON, err := json.Marshal(response)
	if err != nil {
		session.cancel()
		unregisterMCPSession(sessionID)
		writeError(w, r, http.StatusInternalServerError, "failed to marshal response")
		return
	}

	w.Header().Set("MCP-Session-Id", sessionID)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(respJSON)

	slog.Debug("MCP session created", "session_id", sessionID, "token_id", token.ID)
}

// processMCPRequest routes a JSON-RPC request to the appropriate handler.
func (h *Handler) processMCPRequest(ctx context.Context, req *jsonRPCRequest) *jsonRPCResponse {
	switch req.Method {
	case "initialize":
		return h.mcpInitialize(req)
	case "tools/list":
		return h.mcpToolsList(req)
	case "tools/call":
		return h.mcpToolsCall(ctx, req)
	case "notifications/initialized":
		return nil
	default:
		return &jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error:   &jsonRPCError{Code: -32601, Message: "Method not found: " + req.Method},
		}
	}
}

func (h *Handler) mcpInitialize(req *jsonRPCRequest) *jsonRPCResponse {
	result, _ := json.Marshal(map[string]any{
		"protocolVersion": "2025-03-26",
		"capabilities": map[string]any{
			"tools": map[string]any{},
		},
		"serverInfo": map[string]string{
			"name":    "henkaipan-mcp",
			"version": "1.0.0",
		},
	})
	return &jsonRPCResponse{JSONRPC: "2.0", ID: req.ID, Result: result}
}

// ── Tools / List ──────────────────────────────────────────────────────────

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

	result, _ := json.Marshal(map[string]any{"tools": tools})
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
		projects, err = h.store.Apps.ListStandaloneByPattern(ctx, params.Pattern)
	} else {
		projects, err = h.store.Apps.ListAllProjects(ctx, params.Filter)
	}
	if err != nil {
		return mcpError(req, -32603, "Failed to list projects: "+err.Error())
	}

	result, _ := json.Marshal(map[string]any{"projects": projects})
	return &jsonRPCResponse{JSONRPC: "2.0", ID: req.ID, Result: result}
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

	result, _ := json.Marshal(map[string]any{"project": project})
	return &jsonRPCResponse{JSONRPC: "2.0", ID: req.ID, Result: result}
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

	result, _ := json.Marshal(map[string]any{
		"scan_ids": scanIDs,
		"batch_id": batchID,
		"status":   "accepted",
	})
	return &jsonRPCResponse{JSONRPC: "2.0", ID: req.ID, Result: result}
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

	result, _ := json.Marshal(map[string]any{
		"scan":     scan,
		"findings": findings,
	})
	return &jsonRPCResponse{JSONRPC: "2.0", ID: req.ID, Result: result}
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
	})
	if err != nil {
		return mcpError(req, -32603, "Failed to query findings: "+err.Error())
	}

	result, _ := json.Marshal(map[string]any{
		"findings": findings,
		"total":    total,
		"page":     params.Page,
		"limit":    params.Limit,
	})
	return &jsonRPCResponse{JSONRPC: "2.0", ID: req.ID, Result: result}
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

	result, _ := json.Marshal(map[string]any{
		"vulnerabilities": vulns,
		"total":           total,
		"page":            params.Page,
		"limit":           params.Limit,
	})
	return &jsonRPCResponse{JSONRPC: "2.0", ID: req.ID, Result: result}
}

func (h *Handler) mcpDashboardSummary(ctx context.Context, req *jsonRPCRequest, args json.RawMessage) *jsonRPCResponse {
	metrics, err := h.store.Metrics.Summary(ctx)
	if err != nil {
		return mcpError(req, -32603, "Failed to get dashboard summary: "+err.Error())
	}

	result, _ := json.Marshal(map[string]any{"summary": metrics})
	return &jsonRPCResponse{JSONRPC: "2.0", ID: req.ID, Result: result}
}

// ── Helpers ───────────────────────────────────────────────────────────────

func mcpError(req *jsonRPCRequest, code int, message string) *jsonRPCResponse {
	return &jsonRPCResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Error:   &jsonRPCError{Code: code, Message: message},
	}
}
