package handlers

import (
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

func (h *Handler) GetVulnerabilityEngineSummary(w http.ResponseWriter, r *http.Request) {
	summary, err := h.store.Vulnerabilities.GetProjectEngineSummaries(r.Context())
	if err != nil {
		slog.ErrorContext(r.Context(), "failed to get vuln engine summary", "error", err)
		writeError(w, r, http.StatusInternalServerError, "failed to get vulnerability engine summary")
		return
	}
	writeJSON(w, http.StatusOK, summary)
}