package handlers

import (
	"net/http"
	"strconv"
)

func (h *Handler) GetMetricsSummary(w http.ResponseWriter, r *http.Request) {
	m, err := h.store.Metrics.Summary(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to get metrics")
		return
	}
	writeJSON(w, http.StatusOK, m)
}

func (h *Handler) GetTrends(w http.ResponseWriter, r *http.Request) {
	days, _ := strconv.Atoi(r.URL.Query().Get("days"))
	points, err := h.store.Metrics.Trends(r.Context(), days)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to get trends")
		return
	}
	writeJSON(w, http.StatusOK, points)
}

func (h *Handler) GetRiskScores(w http.ResponseWriter, r *http.Request) {
	scores, err := h.store.Metrics.RiskScores(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to get risk scores")
		return
	}
	writeJSON(w, http.StatusOK, scores)
}

func (h *Handler) GetTeamMetrics(w http.ResponseWriter, r *http.Request) {
	metrics, err := h.store.Metrics.TeamMetrics(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to get team metrics")
		return
	}
	writeJSON(w, http.StatusOK, metrics)
}

func (h *Handler) GetSLACompliance(w http.ResponseWriter, r *http.Request) {
	s, err := h.store.Metrics.SLACompliance(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to get SLA compliance")
		return
	}
	writeJSON(w, http.StatusOK, s)
}
