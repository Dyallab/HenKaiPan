package handlers

import (
	"encoding/json"
	"errors"
	"net/http"

	"aspm/internal/repository"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
)

type scheduleCreateReq struct {
	ProjectID string `json:"project_id"`
	Scanner   string `json:"scanner"`
	CronExpr  string `json:"cron_expr"`
}

type scheduleUpdateReq struct {
	Scanner  *string `json:"scanner,omitempty"`
	CronExpr *string `json:"cron_expr,omitempty"`
	Enabled  *bool   `json:"enabled,omitempty"`
}

func (h *Handler) ListSchedules(w http.ResponseWriter, r *http.Request) {
	projectID := r.URL.Query().Get("project_id")
	if projectID != "" {
		schedules, err := h.store.Schedules.ListByProject(r.Context(), projectID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "list schedules: "+err.Error())
			return
		}
		writeJSON(w, http.StatusOK, schedules)
		return
	}

	// If no project_id, return all enabled schedules (admin use)
	schedules, err := h.store.Schedules.ListEnabled(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list schedules: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, schedules)
}

func (h *Handler) GetSchedule(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "scheduleID")
	schedule, err := h.store.Schedules.GetByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusNotFound, "schedule not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "get schedule: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, schedule)
}

func (h *Handler) CreateSchedule(w http.ResponseWriter, r *http.Request) {
	var req scheduleCreateReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if req.ProjectID == "" || req.Scanner == "" || req.CronExpr == "" {
		writeError(w, http.StatusBadRequest, "project_id, scanner, and cron_expr are required")
		return
	}

	schedule, err := h.store.Schedules.Create(r.Context(), repository.ScanScheduleCreate{
		ProjectID: req.ProjectID,
		Scanner:   req.Scanner,
		CronExpr:  req.CronExpr,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "create schedule: "+err.Error())
		return
	}

	h.auditLog(r, "create", "schedule", schedule.ID, nil, schedule)
	writeJSON(w, http.StatusCreated, schedule)
}

func (h *Handler) UpdateSchedule(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "scheduleID")
	var req scheduleUpdateReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	schedule, err := h.store.Schedules.Update(r.Context(), id, repository.ScanScheduleUpdate{
		Scanner:  req.Scanner,
		CronExpr: req.CronExpr,
		Enabled:  req.Enabled,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusNotFound, "schedule not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "update schedule: "+err.Error())
		return
	}

	h.auditLog(r, "update", "schedule", id, nil, schedule)
	writeJSON(w, http.StatusOK, schedule)
}

func (h *Handler) DeleteSchedule(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "scheduleID")
	if err := h.store.Schedules.Delete(r.Context(), id); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusNotFound, "schedule not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "delete schedule: "+err.Error())
		return
	}

	h.auditLog(r, "delete", "schedule", id, nil, nil)
	w.WriteHeader(http.StatusNoContent)
}
