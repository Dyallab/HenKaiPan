package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"aspm/internal/auth"
	"aspm/internal/datascope"
	"aspm/internal/repository"

	"github.com/go-chi/chi/v5"
)

func parseTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Now().AddDate(0, 3, 0) // Default: 3 months
	}
	return t
}

func (h *Handler) ListAuditLogs(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("user_id")
	entityType := r.URL.Query().Get("entity_type")
	action := r.URL.Query().Get("action")

	claims := auth.GetClaims(r)
	scope := datascope.Admin()
	if claims != nil && claims.Role != "admin" {
		scope = datascope.ForUser(claims.UserID)
	}

	logs, total, err := h.store.Audit.List(r.Context(), repository.AuditFilter{
		UserID:     userID,
		EntityType: entityType,
		Action:     action,
		Page:       1,
		Limit:      100,
		Scope:      scope,
	})
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "failed to list audit logs")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"logs":  logs,
		"total": total,
	})
}

func (h *Handler) CreateRiskAcceptance(w http.ResponseWriter, r *http.Request) {
	var body struct {
		FindingID string `json:"finding_id"`
		Rationale string `json:"rationale"`
		ExpiresAt string `json:"expires_at"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid body")
		return
	}
	if body.FindingID == "" || body.Rationale == "" || body.ExpiresAt == "" {
		writeError(w, r, http.StatusBadRequest, "finding_id, rationale, expires_at required")
		return
	}

	// Get current user from context (set by JWT middleware)
	claims := auth.GetClaims(r)
	if claims == nil {
		writeError(w, r, http.StatusUnauthorized, "unauthorized")
		return
	}
	userID := claims.UserID

	ra, err := h.store.RiskAcceptance.Create(r.Context(), repository.RiskAcceptanceCreate{
		FindingID: body.FindingID,
		UserID:    userID,
		Rationale: body.Rationale,
		ExpiresAt: parseTime(body.ExpiresAt),
		Status:    "pending",
	})
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "failed to create risk acceptance")
		return
	}

	h.auditLog(r, "risk_acceptance.create", "risk_acceptance", ra.ID, nil, ra)

	writeJSON(w, http.StatusCreated, ra)
}

func (h *Handler) ApproveRiskAcceptance(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ReviewNotes string `json:"review_notes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid body")
		return
	}

	claims := auth.GetClaims(r)
	if claims == nil {
		writeError(w, r, http.StatusUnauthorized, "unauthorized")
		return
	}
	userID := claims.UserID

	if err := h.store.RiskAcceptance.Approve(r.Context(), chi.URLParam(r, "id"), userID, body.ReviewNotes); err != nil {
		writeError(w, r, http.StatusInternalServerError, "failed to approve risk acceptance")
		return
	}

	h.auditLog(r, "risk_acceptance.approve", "risk_acceptance", chi.URLParam(r, "id"), nil, map[string]string{"status": "approved", "approved_by": userID})

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) RejectRiskAcceptance(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ReviewNotes string `json:"review_notes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid body")
		return
	}

	if err := h.store.RiskAcceptance.Reject(r.Context(), chi.URLParam(r, "id"), body.ReviewNotes); err != nil {
		writeError(w, r, http.StatusInternalServerError, "failed to reject risk acceptance")
		return
	}

	h.auditLog(r, "risk_acceptance.reject", "risk_acceptance", chi.URLParam(r, "id"), nil, map[string]string{"status": "rejected"})

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) ListRiskAcceptances(w http.ResponseWriter, r *http.Request) {
	status := r.URL.Query().Get("status")
	findingID := r.URL.Query().Get("finding_id")

	ras, total, err := h.store.RiskAcceptance.List(r.Context(), repository.RiskAcceptanceFilter{
		Status:    status,
		FindingID: findingID,
		Page:      1,
		Limit:     50,
	})
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "failed to list risk acceptances")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"acceptances": ras,
		"total":       total,
	})
}

func (h *Handler) GetRiskAcceptanceByFinding(w http.ResponseWriter, r *http.Request) {
	findingID := chi.URLParam(r, "id")

	ra, err := h.store.RiskAcceptance.GetByFindingID(r.Context(), findingID)
	if err != nil {
		writeError(w, r, http.StatusNotFound, "no risk acceptance found for this finding")
		return
	}

	writeJSON(w, http.StatusOK, ra)
}
