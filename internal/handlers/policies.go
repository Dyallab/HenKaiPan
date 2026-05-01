package handlers

import (
	"encoding/json"
	"net/http"

	"aspm/internal/models"
	"aspm/internal/repository"

	"github.com/go-chi/chi/v5"
)

func (h *Handler) ListPolicies(w http.ResponseWriter, r *http.Request) {
	policies, err := h.store.Policies.List(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list policies")
		return
	}
	writeJSON(w, http.StatusOK, policies)
}

func (h *Handler) CreatePolicy(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name               string                   `json:"name"`
		Description        string                   `json:"description"`
		Conditions         []models.PolicyCondition `json:"conditions"`
		Actions            []models.PolicyAction    `json:"actions"`
		PackType           string                   `json:"pack_type"`
		ComplianceControls []string                 `json:"compliance_controls"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	if body.Name == "" {
		writeError(w, http.StatusBadRequest, "name required")
		return
	}

	validFields := map[string]bool{"severity": true, "scanner": true, "rule_id": true, "file_path": true}
	validOps := map[string]bool{"eq": true, "contains": true}
	for _, c := range body.Conditions {
		if !validFields[c.Field] || !validOps[c.Op] {
			writeError(w, http.StatusBadRequest, "invalid condition field or op")
			return
		}
	}
	validActionTypes := map[string]bool{"set_status": true, "assign": true}
	for _, a := range body.Actions {
		if !validActionTypes[a.Type] {
			writeError(w, http.StatusBadRequest, "invalid action type")
			return
		}
	}

	p, err := h.store.Policies.Create(r.Context(), repository.PolicyCreate{
		Name: body.Name, Description: body.Description, Conditions: body.Conditions, Actions: body.Actions,
		PackType: body.PackType, ComplianceControls: body.ComplianceControls,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create policy")
		return
	}

	h.auditLog(r, "policy.create", "policy", p.ID, nil, p)

	writeJSON(w, http.StatusCreated, p)
}

func (h *Handler) UpdatePolicy(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Enabled *bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	if body.Enabled == nil {
		writeError(w, http.StatusBadRequest, "enabled required")
		return
	}

	// Get old policy state for audit
	oldPolicy, _ := h.store.Policies.GetByID(r.Context(), chi.URLParam(r, "id"))

	if err := h.store.Policies.SetEnabled(r.Context(), chi.URLParam(r, "id"), *body.Enabled); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to update policy")
		return
	}

	action := "policy.disable"
	if *body.Enabled {
		action = "policy.enable"
	}
	h.auditLog(r, action, "policy", chi.URLParam(r, "id"), oldPolicy, map[string]bool{"enabled": *body.Enabled})

	writeJSON(w, http.StatusOK, map[string]bool{"enabled": *body.Enabled})
}

func (h *Handler) DeletePolicy(w http.ResponseWriter, r *http.Request) {
	// Get old policy state for audit
	oldPolicy, _ := h.store.Policies.GetByID(r.Context(), chi.URLParam(r, "id"))

	if err := h.store.Policies.Delete(r.Context(), chi.URLParam(r, "id")); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to delete policy")
		return
	}

	h.auditLog(r, "policy.delete", "policy", chi.URLParam(r, "id"), oldPolicy, nil)

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) ListSuppressions(w http.ResponseWriter, r *http.Request) {
	suppressions, err := h.store.Policies.ListSuppressions(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list suppressions")
		return
	}
	writeJSON(w, http.StatusOK, suppressions)
}

func (h *Handler) CreateSuppression(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name        string  `json:"name"`
		RuleID      *string `json:"rule_id"`
		FilePattern *string `json:"file_pattern"`
		Scanner     *string `json:"scanner"`
		Reason      *string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	if body.Name == "" {
		writeError(w, http.StatusBadRequest, "name required")
		return
	}
	if body.RuleID == nil && body.FilePattern == nil && body.Scanner == nil {
		writeError(w, http.StatusBadRequest, "at least one of rule_id, file_pattern, scanner required")
		return
	}

	s, err := h.store.Policies.CreateSuppression(r.Context(), repository.SuppressionCreate{
		Name: body.Name, RuleID: body.RuleID, FilePattern: body.FilePattern,
		Scanner: body.Scanner, Reason: body.Reason,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create suppression")
		return
	}

	h.auditLog(r, "suppression.create", "suppression", s.ID, nil, s)

	writeJSON(w, http.StatusCreated, s)
}

func (h *Handler) DeleteSuppression(w http.ResponseWriter, r *http.Request) {
	// Get old suppression state for audit
	oldSuppressions, _ := h.store.Policies.ListSuppressions(r.Context())
	var oldSuppression *models.Suppression
	for _, s := range oldSuppressions {
		if s.ID == chi.URLParam(r, "id") {
			oldSuppression = &s
			break
		}
	}

	if err := h.store.Policies.DeleteSuppression(r.Context(), chi.URLParam(r, "id")); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to delete suppression")
		return
	}

	h.auditLog(r, "suppression.delete", "suppression", chi.URLParam(r, "id"), oldSuppression, nil)

	w.WriteHeader(http.StatusNoContent)
}
