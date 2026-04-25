package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
)

func (h *Handler) ListRepos(w http.ResponseWriter, r *http.Request) {
	repos, err := h.store.Repos.List(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list repos")
		return
	}
	writeJSON(w, http.StatusOK, repos)
}

func (h *Handler) CreateRepo(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
		URL  string `json:"url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.URL == "" {
		writeError(w, http.StatusBadRequest, "name and url required")
		return
	}

	repo, err := h.store.Repos.Create(r.Context(), req.Name, req.URL)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create repo")
		return
	}
	writeJSON(w, http.StatusCreated, repo)
}

func (h *Handler) DeleteRepo(w http.ResponseWriter, r *http.Request) {
	if err := h.store.Repos.Delete(r.Context(), chi.URLParam(r, "id")); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to delete repo")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
