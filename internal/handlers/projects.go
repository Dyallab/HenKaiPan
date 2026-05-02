package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"

	"aspm/internal/repository"

	"github.com/go-chi/chi/v5"
)

func (h *Handler) ListProjects(w http.ResponseWriter, r *http.Request) {
	appID := chi.URLParam(r, "id")
	if appID != "" {
		projects, err := h.store.Apps.ListProjects(r.Context(), appID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to list projects")
			return
		}
		writeJSON(w, http.StatusOK, projects)
		return
	}

	filter := r.URL.Query().Get("filter")
	projects, err := h.store.Apps.ListAllProjects(r.Context(), filter)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list projects")
		return
	}
	writeJSON(w, http.StatusOK, projects)
}

func (h *Handler) GetProject(w http.ResponseWriter, r *http.Request) {
	p, err := h.store.Apps.GetProjectByID(r.Context(), chi.URLParam(r, "projectID"))
	if err != nil {
		writeError(w, http.StatusNotFound, "project not found")
		return
	}
	writeJSON(w, http.StatusOK, p)
}

func (h *Handler) CreateProject(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name          string  `json:"name"`
		Description   string  `json:"description"`
		AppID         *string `json:"app_id"`
		RepoURL       string  `json:"repo_url"`
		Provider      string  `json:"provider"`
		DefaultBranch string  `json:"default_branch"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Name == "" {
		writeError(w, http.StatusBadRequest, "name required")
		return
	}

	pc := repository.ProjectCreate{
		Name: body.Name, Description: body.Description,
		RepoURL: body.RepoURL, Provider: body.Provider, DefaultBranch: body.DefaultBranch,
	}

	if body.AppID != nil && *body.AppID != "" {
		project, err := h.store.Apps.CreateProject(r.Context(), *body.AppID, pc)
		if err != nil {
			writeError(w, http.StatusConflict, err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, project)
	} else {
		project, err := h.store.Apps.CreateStandaloneProject(r.Context(), pc)
		if err != nil {
			writeError(w, http.StatusConflict, err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, project)
	}
}

func (h *Handler) UpdateProject(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name           *string `json:"name"`
		Description    *string `json:"description"`
		RepoURL        *string `json:"repo_url"`
		Provider       *string `json:"provider"`
		DefaultBranch  *string `json:"default_branch"`
		ExternalRepoID *string `json:"external_repo_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	h.store.Apps.UpdateProject(r.Context(), chi.URLParam(r, "projectID"), repository.ProjectUpdate{
		Name: body.Name, Description: body.Description,
		RepoURL: body.RepoURL, Provider: body.Provider, DefaultBranch: body.DefaultBranch,
		ExternalRepoID: body.ExternalRepoID,
	})
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) UpdateProjectGitHubToken(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "projectID")

	var req struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if err := h.store.Apps.UpdateProjectGitHubToken(r.Context(), id, req.Token); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to update token")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) DeleteProject(w http.ResponseWriter, r *http.Request) {
	h.store.Apps.DeleteProject(r.Context(), chi.URLParam(r, "projectID"))
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) GetCoverageReport(w http.ResponseWriter, r *http.Request) {
	days := 0
	if d := r.URL.Query().Get("days"); d != "" {
		fmt.Sscanf(d, "%d", &days)
	}

	report, err := h.store.Apps.GetCoverageReport(r.Context(), days)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to get coverage report")
		return
	}
	writeJSON(w, http.StatusOK, report)
}
