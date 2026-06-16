package handlers

import "net/http"

type LimitsResponse struct {
	MaxProjects int `json:"max_projects"`
	Projects    int `json:"projects"`
	MaxUsers    int `json:"max_users"`
	Users       int `json:"users"`
	MaxAIScans  int `json:"max_ai_scans"`
	AIScans     int `json:"ai_scans"`
}

func (h *Handler) GetLimits(w http.ResponseWriter, r *http.Request) {
	resp := LimitsResponse{
		MaxProjects: h.maxProjects,
		MaxUsers:    h.maxUsers,
		MaxAIScans:  h.maxAIScans,
	}

	if n, err := h.store.Apps.CountProjects(r.Context()); err == nil {
		resp.Projects = n
	}
	if n, err := h.store.Users.Count(r.Context()); err == nil {
		resp.Users = n
	}
	if n, err := h.store.Usage.GetAIScanCount(r.Context(), monthKey()); err == nil {
		resp.AIScans = n
	}

	writeJSON(w, http.StatusOK, resp)
}
