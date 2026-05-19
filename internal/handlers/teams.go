package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
)

func (h *Handler) ListTeams(w http.ResponseWriter, r *http.Request) {
	teams, err := h.store.Teams.List(r.Context())
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "failed to list teams")
		return
	}
	writeJSON(w, http.StatusOK, teams)
}

func (h *Handler) CreateTeam(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Name == "" {
		writeError(w, r, http.StatusBadRequest, "name required")
		return
	}

	t, err := h.store.Teams.Create(r.Context(), body.Name)
	if err != nil {
		writeError(w, r, http.StatusConflict, "team name already exists")
		return
	}
	writeJSON(w, http.StatusCreated, t)
}

func (h *Handler) DeleteTeam(w http.ResponseWriter, r *http.Request) {
	h.store.Teams.Delete(r.Context(), chi.URLParam(r, "id"))
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) AddTeamMember(w http.ResponseWriter, r *http.Request) {
	var body struct {
		UserID string `json:"user_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.UserID == "" {
		writeError(w, r, http.StatusBadRequest, "user_id required")
		return
	}

	if err := h.store.Teams.AddMember(r.Context(), chi.URLParam(r, "id"), body.UserID); err != nil {
		writeError(w, r, http.StatusInternalServerError, "failed to add member")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) RemoveTeamMember(w http.ResponseWriter, r *http.Request) {
	h.store.Teams.RemoveMember(r.Context(), chi.URLParam(r, "id"), chi.URLParam(r, "userID"))
	w.WriteHeader(http.StatusNoContent)
}
