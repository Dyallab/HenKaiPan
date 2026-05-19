package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"aspm/internal/github"
	"aspm/internal/repository"
	"aspm/internal/validation"

	"github.com/go-chi/chi/v5"
)

func (h *Handler) ListProjects(w http.ResponseWriter, r *http.Request) {
	appID := chi.URLParam(r, "id")
	if appID != "" {
		projects, err := h.store.Apps.ListProjects(r.Context(), appID)
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "failed to list projects")
			return
		}
		writeJSON(w, http.StatusOK, projects)
		return
	}

	filter := r.URL.Query().Get("filter")
	pattern := r.URL.Query().Get("pattern")

	// If pattern is set, delegate to pattern-based lookup
	if pattern != "" {
		projects, err := h.store.Apps.ListStandaloneByPattern(r.Context(), pattern)
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "failed to list projects")
			return
		}
		writeJSON(w, http.StatusOK, projects)
		return
	}

	projects, err := h.store.Apps.ListAllProjects(r.Context(), filter)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "failed to list projects")
		return
	}
	writeJSON(w, http.StatusOK, projects)
}

func (h *Handler) GetProject(w http.ResponseWriter, r *http.Request) {
	p, err := h.store.Apps.GetProjectByID(r.Context(), chi.URLParam(r, "projectID"))
	if err != nil {
		writeError(w, r, http.StatusNotFound, "project not found")
		return
	}
	writeJSON(w, http.StatusOK, p)
}

func (h *Handler) CreateProject(w http.ResponseWriter, r *http.Request) {
	var req validation.CreateProjectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid body")
		return
	}

	if validationErrs := validation.ValidateStruct(req); validationErrs != nil {
		h.writeValidationErrors(w, r, validationErrs)
		return
	}

	pc := repository.ProjectCreate{
		Name: req.Name, Description: req.Description,
		RepoURL: req.RepoURL, Provider: req.Provider,
		DefaultBranch: req.DefaultBranch,
	}

	appID := r.URL.Query().Get("app_id")
	if appID != "" {
		project, err := h.store.Apps.CreateProject(r.Context(), appID, pc)
	if err != nil {
			writeError(w, r, http.StatusConflict, "project already exists")
			return
		}
		writeJSON(w, http.StatusCreated, project)
	} else {
		project, err := h.store.Apps.CreateStandaloneProject(r.Context(), pc)
		if err != nil {
			writeError(w, r, http.StatusConflict, "project already exists")
			return
		}
		h.auditLog(r, "project.create", "project", project.ID, nil, project)
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
		AppID          *string `json:"app_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid body")
		return
	}
	projectID := chi.URLParam(r, "projectID")
	oldProject, _ := h.store.Apps.GetProjectByID(r.Context(), projectID)
	h.store.Apps.UpdateProject(r.Context(), projectID, repository.ProjectUpdate{
		Name: body.Name, Description: body.Description,
		RepoURL: body.RepoURL, Provider: body.Provider, DefaultBranch: body.DefaultBranch,
		ExternalRepoID: body.ExternalRepoID,
		AppID: body.AppID,
	})
	h.auditLog(r, "project.update", "project", projectID, oldProject, nil)
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) UpdateProjectGitHubToken(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "projectID")

	oldProject, _ := h.store.Apps.GetProjectByID(r.Context(), id)

	var req struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid request body")
		return
	}

	var expiresAt *time.Time
	if req.Token != "" {
		v := github.ValidateToken(r.Context(), req.Token)
		if !v.Valid {
			writeError(w, r, http.StatusBadRequest, v.Error)
			return
		}
		expiresAt = v.ExpiresAt
	}

	if err := h.store.Apps.UpdateProjectGitHubToken(r.Context(), id, req.Token, expiresAt); err != nil {
		writeError(w, r, http.StatusInternalServerError, "failed to update token")
		return
	}

	action := "project.token.set"
	if req.Token == "" {
		action = "project.token.remove"
	}
	h.auditLog(r, action, "project", id, oldProject, nil)

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) DeleteProject(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "projectID")
	oldProject, _ := h.store.Apps.GetProjectByID(r.Context(), id)
	h.store.Apps.DeleteProject(r.Context(), id)
	h.auditLog(r, "project.delete", "project", id, oldProject, nil)
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) GetCoverageReport(w http.ResponseWriter, r *http.Request) {
	days := 0
	if d := r.URL.Query().Get("days"); d != "" {
		fmt.Sscanf(d, "%d", &days)
	}

	report, err := h.store.Apps.GetCoverageReport(r.Context(), days)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "failed to get coverage report")
		return
	}
	writeJSON(w, http.StatusOK, report)
}

type bulkCreateRequest struct {
	Pattern     string `json:"pattern"`
	AppID       string `json:"app_id,omitempty"`
	GitHubToken string `json:"github_token,omitempty"`
	Limit       int    `json:"limit,omitempty"`
	Preview     bool   `json:"preview,omitempty"`
}

type bulkProjectResult struct {
	Name        string `json:"name"`
	RepoURL     string `json:"repo_url"`
	Status      string `json:"status"`
	Error       string `json:"error,omitempty"`
	ProjectID   string `json:"project_id,omitempty"`
}

type bulkCreateResponse struct {
	Created  int                  `json:"created"`
	Skipped  int                  `json:"skipped"`
	Errors   int                  `json:"errors"`
	Projects []bulkProjectResult `json:"projects"`
}

func (h *Handler) BulkCreateProjects(w http.ResponseWriter, r *http.Request) {
	var req bulkCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid body")
		return
	}
	if req.Pattern == "" {
		writeError(w, r, http.StatusBadRequest, "pattern is required")
		return
	}
	if req.Limit <= 0 {
		req.Limit = 50
	}
	if req.Limit > 500 {
		req.Limit = 500
	}

	repos, err := github.ResolvePattern(r.Context(), req.Pattern, req.GitHubToken, req.Limit)
	if err != nil {
		writeError(w, r, http.StatusBadRequest, err.Error())
		return
	}
	if len(repos) == 0 {
		writeJSON(w, http.StatusOK, bulkCreateResponse{
			Projects: []bulkProjectResult{},
		})
		return
	}

	var resp bulkCreateResponse

	if req.Preview {
		resp.Projects = make([]bulkProjectResult, len(repos))
		for i, repo := range repos {
			resp.Projects[i] = bulkProjectResult{
				Name:    repo.Name,
				RepoURL: repo.RepoURL,
				Status:  "found",
			}
		}
		writeJSON(w, http.StatusOK, resp)
		return
	}

	projects := make([]repository.ProjectCreate, len(repos))
	for i, repo := range repos {
		projects[i] = repository.ProjectCreate{
			Name:          repo.Name,
			Description:   repo.Description,
			RepoURL:       repo.RepoURL,
			Provider:      "github",
			DefaultBranch: repo.DefaultBranch,
		}
	}

	results, err := h.store.Apps.BulkCreateProjects(r.Context(), req.AppID, projects)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "failed to bulk create projects")
		return
	}

	resp.Projects = make([]bulkProjectResult, len(results))
	for i, r := range results {
		resp.Projects[i] = bulkProjectResult{
			Name:    r.Name,
			RepoURL: r.RepoURL,
		}
		if r.Created {
			resp.Projects[i].Status = "created"
			resp.Projects[i].ProjectID = r.ProjectID
			resp.Created++
		} else {
			resp.Projects[i].Status = "skipped"
			resp.Skipped++
		}
	}

	writeJSON(w, http.StatusOK, resp)
}

func (h *Handler) BulkAssignProjects(w http.ResponseWriter, r *http.Request) {
	var req struct {
		AppID      string   `json:"app_id"`
		ProjectIDs []string `json:"project_ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid body")
		return
	}
	if req.AppID == "" {
		writeError(w, r, http.StatusBadRequest, "app_id is required")
		return
	}
	if len(req.ProjectIDs) == 0 {
		writeError(w, r, http.StatusBadRequest, "project_ids is required")
		return
	}

	count, err := h.store.Apps.AssignProjectsToApp(r.Context(), req.AppID, req.ProjectIDs)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "failed to assign projects")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"assigned": count,
	})
}
