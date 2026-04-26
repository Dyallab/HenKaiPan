package handlers

import (
	"encoding/json"
	"net/http"

	"aspm/internal/repository"

	"github.com/go-chi/chi/v5"
)

func (h *Handler) ListApps(w http.ResponseWriter, r *http.Request) {
	apps, err := h.store.Apps.List(r.Context(), r.URL.Query().Get("team_id"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list apps")
		return
	}
	writeJSON(w, http.StatusOK, apps)
}

func (h *Handler) CreateApp(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name        string  `json:"name"`
		Description string  `json:"description"`
		TeamID      *string `json:"team_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Name == "" {
		writeError(w, http.StatusBadRequest, "name required")
		return
	}

	a, err := h.store.Apps.Create(r.Context(), body.Name, body.Description, body.TeamID)
	if err != nil {
		writeError(w, http.StatusConflict, "app name already exists")
		return
	}
	writeJSON(w, http.StatusCreated, a)
}

func (h *Handler) GetApp(w http.ResponseWriter, r *http.Request) {
	a, err := h.store.Apps.Get(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	writeJSON(w, http.StatusOK, a)
}

func (h *Handler) UpdateApp(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name        *string `json:"name"`
		Description *string `json:"description"`
		TeamID      *string `json:"team_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	h.store.Apps.Update(r.Context(), chi.URLParam(r, "id"), repository.AppUpdate{
		Name: body.Name, Description: body.Description, TeamID: body.TeamID,
	})
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) DeleteApp(w http.ResponseWriter, r *http.Request) {
	h.store.Apps.Delete(r.Context(), chi.URLParam(r, "id"))
	w.WriteHeader(http.StatusNoContent)
}
