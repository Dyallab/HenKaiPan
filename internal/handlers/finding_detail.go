package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"aspm/internal/cache"
	"aspm/internal/models"

	"github.com/go-chi/chi/v5"
)

// findingDetailResponse is the composite response for GET /api/findings/{id}/detail.
// Each sub-section is nullable — if a query fails the key is null, not an error.
type findingDetailResponse struct {
	Finding        *models.Finding        `json:"finding"`
	Correlations   *correlationsPayload   `json:"correlations"`
	Analysis       *models.AgentAnalysis  `json:"analysis"`
	JiraIssue      *models.JiraIssueLink  `json:"jira_issue"`
	RiskAcceptance *models.RiskAcceptance `json:"risk_acceptance"`
}

// correlationsPayload mirrors the shape returned by GetFindingCorrelations.
type correlationsPayload struct {
	Findings []models.Finding `json:"findings"`
	Total    int              `json:"total"`
}

// cacheKey returns the Redis key for the finding detail cache entry.
func findingDetailCacheKey(id string) string { return id + ":detail" }

// GetFindingDetail returns a single finding along with its correlations,
// analysis, Jira issue link, and risk acceptance in one response.
func (h *Handler) GetFindingDetail(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	// ── 1. Check cache ───────────────────────────────────────────────────────
	if h.FindingCache != nil {
		if cached, err := h.FindingCache.Get(r.Context(), findingDetailCacheKey(id)); err == nil && cached != "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(cached))
			return
		}
	}

	// ── 2. Query finding (required) ──────────────────────────────────────────
	finding, err := h.store.Findings.GetByID(r.Context(), id)
	if err != nil {
		writeError(w, r, http.StatusNotFound, "finding not found")
		return
	}
	h.normalizeFindingForDisplay(finding)

	// ── 3. Query optional sub-sections (safe to fail → null) ─────────────────
	resp := findingDetailResponse{Finding: finding}

	// Correlations
	if corrFindings, corrErr := h.store.Agents.GetCorrelatedFindings(r.Context(), id); corrErr == nil {
		resp.Correlations = &correlationsPayload{
			Findings: corrFindings,
			Total:    len(corrFindings),
		}
	} else {
		slog.Debug("finding detail: correlations not found", "finding_id", id, "err", corrErr)
	}

	// Analysis
	if analysis, analysisErr := h.store.Agents.GetAnalysis(r.Context(), id, "validator"); analysisErr == nil {
		resp.Analysis = analysis
	} else {
		slog.Debug("finding detail: analysis not found", "finding_id", id, "err", analysisErr)
	}

	// Jira issue
	if jiraIssue, jiraErr := h.store.Settings.GetJiraIssueLinkByFindingID(r.Context(), id); jiraErr == nil {
		resp.JiraIssue = jiraIssue
	} else {
		slog.Debug("finding detail: jira issue not found", "finding_id", id, "err", jiraErr)
	}

	// Risk acceptance
	if ra, raErr := h.store.RiskAcceptance.GetByFindingID(r.Context(), id); raErr == nil {
		resp.RiskAcceptance = ra
	} else {
		slog.Debug("finding detail: risk acceptance not found", "finding_id", id, "err", raErr)
	}

	// ── 4. Serialize response ────────────────────────────────────────────────
	body, err := json.Marshal(resp)
	if err != nil {
		h.writeInternal(w, r, err, "failed to marshal response")
		return
	}

	// ── 5. Set cache ─────────────────────────────────────────────────────────
	if h.FindingCache != nil {
		if cerr := h.FindingCache.Set(r.Context(), findingDetailCacheKey(id), string(body), cache.DefaultTTL); cerr != nil {
			slog.Warn("finding detail: failed to set cache", "finding_id", id, "err", cerr)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}
