package handlers

import (
	"net/http"

	"aspm/internal/pagination"
	"aspm/internal/repository"

	"github.com/go-chi/chi/v5"
)

func (h *Handler) ListVulnerabilities(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	p := pagination.FromQueryWithDefaults(q, 100, 200)

	vulns, total, err := h.store.Vulns.List(r.Context(), repository.VulnFilter{
		Severities: parseCSVParam(q.Get("severity")),
		Search:     q.Get("q"),
		OnlyOpen:   q.Get("open") != "false",
		Page:       p.Page,
		Limit:      p.Limit,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list vulnerabilities")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"vulnerabilities": vulns, "total": total})
}

func (h *Handler) GetVulnerabilityAffected(w http.ResponseWriter, r *http.Request) {
	affected, err := h.store.Vulns.GetAffected(r.Context(), chi.URLParam(r, "vulnID"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to get affected repos")
		return
	}
	writeJSON(w, http.StatusOK, affected)
}
