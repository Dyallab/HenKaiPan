package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"aspm/internal/pagination"
	"aspm/internal/repository"

	"github.com/go-chi/chi/v5"
)

func (h *Handler) ListVulnerabilities(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	p := pagination.FromQueryWithDefaults(q, 100, 200)

	vulns, total, err := h.store.Vulnerabilities.List(r.Context(), repository.VulnerabilityFilter{
		ProjectID:  q.Get("project_id"),
		Severities: parseCSVParam(q.Get("severity")),
		EngineType: q.Get("engine_type"),
		Status:     q.Get("status"),
		Search:     q.Get("q"),
		OnlyOpen:   q.Get("open") != "false",
		Page:       p.Page,
		Limit:      p.Limit,
		SortBy:     q.Get("sort"),
	})
	if err != nil {
		slog.ErrorContext(r.Context(), "failed to list vulnerabilities", "error", err)
		writeError(w, r, http.StatusInternalServerError, "failed to list vulnerabilities")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"vulnerabilities": vulns, "total": total})
}

func (h *Handler) GetVulnerabilityAffected(w http.ResponseWriter, r *http.Request) {
	findings, err := h.store.Vulnerabilities.GetAffectedFindings(r.Context(), chi.URLParam(r, "vulnID"))
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "failed to get vulnerability findings")
		return
	}
	writeJSON(w, http.StatusOK, findings)
}

func (h *Handler) UpdateVulnerabilityStatus(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "vulnID")

	var req struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid request body")
		return
	}

	validStatuses := map[string]bool{"open": true, "in_review": true, "accepted_risk": true, "fixed": true, "verified": true}
	if !validStatuses[req.Status] {
		writeError(w, r, http.StatusBadRequest, "invalid status: must be one of open, in_review, accepted_risk, fixed, verified")
		return
	}

	if err := h.store.Vulnerabilities.UpdateStatus(r.Context(), id, req.Status); err != nil {
		slog.ErrorContext(r.Context(), "failed to update vulnerability status", "error", err, "vuln_id", id)
		writeError(w, r, http.StatusInternalServerError, "failed to update vulnerability status")
		return
	}

	vuln, err := h.store.Vulnerabilities.GetByID(r.Context(), id)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "vulnerability not found after update")
		return
	}

	writeJSON(w, http.StatusOK, vuln)
}

func (h *Handler) GetVulnerabilityEngineSummary(w http.ResponseWriter, r *http.Request) {
	summary, err := h.store.Vulnerabilities.GetProjectEngineSummaries(r.Context())
	if err != nil {
		slog.ErrorContext(r.Context(), "failed to get vuln engine summary", "error", err)
		writeError(w, r, http.StatusInternalServerError, "failed to get vulnerability engine summary")
		return
	}
	writeJSON(w, http.StatusOK, summary)
}