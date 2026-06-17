package handlers

import (
	"net/http"
	"strconv"

	"aspm/internal/auth"
	"aspm/internal/datascope"
)

func (h *Handler) scopeFromRequest(r *http.Request) datascope.Scope {
	claims := auth.GetClaims(r)
	if claims != nil && claims.Role == "admin" {
		return datascope.Admin()
	}
	if claims != nil {
		return datascope.ForUser(claims.UserID)
	}
	return datascope.Admin()
}

func (h *Handler) GetMetricsSummary(w http.ResponseWriter, r *http.Request) {
	m, err := h.store.Metrics.Summary(r.Context(), h.scopeFromRequest(r))
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "failed to get metrics")
		return
	}
	writeJSON(w, http.StatusOK, m)
}

func (h *Handler) GetTrends(w http.ResponseWriter, r *http.Request) {
	days, _ := strconv.Atoi(r.URL.Query().Get("days"))
	points, err := h.store.Metrics.Trends(r.Context(), h.scopeFromRequest(r), days)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "failed to get trends")
		return
	}
	writeJSON(w, http.StatusOK, points)
}

func (h *Handler) GetRiskScores(w http.ResponseWriter, r *http.Request) {
	scores, err := h.store.Metrics.RiskScores(r.Context(), h.scopeFromRequest(r))
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "failed to get risk scores")
		return
	}
	writeJSON(w, http.StatusOK, scores)
}

func (h *Handler) GetTeamMetrics(w http.ResponseWriter, r *http.Request) {
	metrics, err := h.store.Metrics.TeamMetrics(r.Context(), h.scopeFromRequest(r))
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "failed to get team metrics")
		return
	}
	writeJSON(w, http.StatusOK, metrics)
}

func (h *Handler) GetSLACompliance(w http.ResponseWriter, r *http.Request) {
	s, err := h.store.Metrics.SLACompliance(r.Context(), h.scopeFromRequest(r))
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "failed to get SLA compliance")
		return
	}
	writeJSON(w, http.StatusOK, s)
}

func (h *Handler) GetScannerHealth(w http.ResponseWriter, r *http.Request) {
	health, err := h.store.Metrics.ScannerHealth(r.Context())
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "failed to get scanner health")
		return
	}
	writeJSON(w, http.StatusOK, health)
}

func (h *Handler) GetSecurityScores(w http.ResponseWriter, r *http.Request) {
	var projectID *string
	if pid := r.URL.Query().Get("project_id"); pid != "" {
		projectID = &pid
	}

	scores, err := h.store.Metrics.SecurityScores(r.Context(), h.scopeFromRequest(r), projectID)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "failed to get security scores")
		return
	}
	writeJSON(w, http.StatusOK, scores)
}
