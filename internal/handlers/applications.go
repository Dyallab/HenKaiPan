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
		writeError(w, r, http.StatusInternalServerError, "failed to list apps")
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
		writeError(w, r, http.StatusBadRequest, "name required")
		return
	}

	a, err := h.store.Apps.Create(r.Context(), body.Name, body.Description, body.TeamID)
	if err != nil {
		writeError(w, r, http.StatusConflict, "app name already exists")
		return
	}
	h.auditLog(r, "app.create", "app", a.ID, nil, a)
	writeJSON(w, http.StatusCreated, a)
}

func (h *Handler) GetApp(w http.ResponseWriter, r *http.Request) {
	a, err := h.store.Apps.Get(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, r, http.StatusNotFound, "not found")
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
		writeError(w, r, http.StatusBadRequest, "invalid body")
		return
	}
	id := chi.URLParam(r, "id")
	oldApp, _ := h.store.Apps.Get(r.Context(), id)
	h.store.Apps.Update(r.Context(), id, repository.AppUpdate{
		Name: body.Name, Description: body.Description, TeamID: body.TeamID,
	})
	h.auditLog(r, "app.update", "app", id, oldApp, nil)
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) DeleteApp(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	oldApp, _ := h.store.Apps.Get(r.Context(), id)
	h.store.Apps.Delete(r.Context(), id)
	h.auditLog(r, "app.delete", "app", id, oldApp, nil)
	w.WriteHeader(http.StatusNoContent)
}
