package handlers

import (
	"encoding/json"
	"net/http"

	"aspm/internal/repository"

	"github.com/go-chi/chi/v5"
)

func (h *Handler) ListProjects(w http.ResponseWriter, r *http.Request) {
	projects, err := h.store.Apps.ListProjects(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list projects")
		return
	}
	writeJSON(w, http.StatusOK, projects)
}

func (h *Handler) CreateProject(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name        string  `json:"name"`
		Description string  `json:"description"`
		RepoID      *string `json:"repo_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Name == "" {
		writeError(w, http.StatusBadRequest, "name required")
		return
	}

	p, err := h.store.Apps.CreateProject(r.Context(), chi.URLParam(r, "id"), repository.ProjectCreate{
		Name: body.Name, Description: body.Description, RepoID: body.RepoID,
	})
	if err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, p)
}

func (h *Handler) UpdateProject(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name        *string `json:"name"`
		Description *string `json:"description"`
		RepoID      *string `json:"repo_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	h.store.Apps.UpdateProject(r.Context(), chi.URLParam(r, "projectID"), repository.ProjectUpdate{
		Name: body.Name, Description: body.Description, RepoID: body.RepoID,
	})
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) DeleteProject(w http.ResponseWriter, r *http.Request) {
	h.store.Apps.DeleteProject(r.Context(), chi.URLParam(r, "projectID"))
	w.WriteHeader(http.StatusNoContent)
}
