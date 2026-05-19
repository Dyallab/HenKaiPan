package handlers

import (
	"encoding/json"
	"errors"
	"net/http"

	"aspm/internal/repository"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/robfig/cron/v3"
)

var cronParser = cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)

func validateCronExpr(expr string) error {
	_, err := cronParser.Parse(expr)
	return err
}

type scheduleCreateReq struct {
	ProjectID   string  `json:"project_id"`
	AppID       string  `json:"app_id"`
	Scanner     string  `json:"scanner"`
	ScannerType *string `json:"scanner_type,omitempty"`
	CronExpr    string  `json:"cron_expr"`
}

type scheduleUpdateReq struct {
	Scanner     *string `json:"scanner,omitempty"`
	ScannerType *string `json:"scanner_type,omitempty"`
	CronExpr    *string `json:"cron_expr,omitempty"`
	Enabled     *bool   `json:"enabled,omitempty"`
}

func (h *Handler) ListSchedules(w http.ResponseWriter, r *http.Request) {
	projectID := r.URL.Query().Get("project_id")
	if projectID != "" {
		schedules, err := h.store.Schedules.ListByProject(r.Context(), projectID)
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "failed to list schedules")
			return
		}
		writeJSON(w, http.StatusOK, schedules)
		return
	}

	// If no project_id, return all enabled schedules (admin use)
	schedules, err := h.store.Schedules.ListEnabled(r.Context())
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "failed to list schedules")
		return
	}
	writeJSON(w, http.StatusOK, schedules)
}

func (h *Handler) GetSchedule(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "scheduleID")
	schedule, err := h.store.Schedules.GetByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, r, http.StatusNotFound, "schedule not found")
			return
		}
		writeError(w, r, http.StatusInternalServerError, "failed to get schedule")
		return
	}
	writeJSON(w, http.StatusOK, schedule)
}

func (h *Handler) CreateSchedule(w http.ResponseWriter, r *http.Request) {
	var req scheduleCreateReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid JSON")
		return
	}
	if req.ProjectID == "" && req.AppID == "" {
		writeError(w, r, http.StatusBadRequest, "project_id or app_id is required")
		return
	}
	if req.CronExpr == "" {
		writeError(w, r, http.StatusBadRequest, "cron_expr is required")
		return
	}
	if req.Scanner == "" && req.ScannerType == nil {
		writeError(w, r, http.StatusBadRequest, "scanner or scanner_type is required")
		return
	}

	// Validate cron expression
	if err := validateCronExpr(req.CronExpr); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid cron expression: "+err.Error())
		return
	}

	var appID *string
	if req.AppID != "" {
		appID = &req.AppID
	}

	schedule, err := h.store.Schedules.Create(r.Context(), repository.ScanScheduleCreate{
		ProjectID:   req.ProjectID,
		AppID:       appID,
		Scanner:     req.Scanner,
		ScannerType: req.ScannerType,
		CronExpr:    req.CronExpr,
	})
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "failed to create schedule")
		return
	}

	h.auditLog(r, "schedule.create", "schedule", schedule.ID, nil, schedule)
	writeJSON(w, http.StatusCreated, schedule)
}

func (h *Handler) UpdateSchedule(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "scheduleID")
	var req scheduleUpdateReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid JSON")
		return
	}

	// Validate cron expression if provided
	if req.CronExpr != nil {
		if err := validateCronExpr(*req.CronExpr); err != nil {
			writeError(w, r, http.StatusBadRequest, "invalid cron expression: "+err.Error())
			return
		}
	}

	schedule, err := h.store.Schedules.Update(r.Context(), id, repository.ScanScheduleUpdate{
		Scanner:     req.Scanner,
		ScannerType: req.ScannerType,
		CronExpr:    req.CronExpr,
		Enabled:     req.Enabled,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, r, http.StatusNotFound, "schedule not found")
			return
		}
		writeError(w, r, http.StatusInternalServerError, "failed to update schedule")
		return
	}

	h.auditLog(r, "schedule.update", "schedule", id, nil, schedule)
	writeJSON(w, http.StatusOK, schedule)
}

func (h *Handler) DeleteSchedule(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "scheduleID")
	if err := h.store.Schedules.Delete(r.Context(), id); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, r, http.StatusNotFound, "schedule not found")
			return
		}
		writeError(w, r, http.StatusInternalServerError, "failed to delete schedule")
		return
	}

	h.auditLog(r, "schedule.delete", "schedule", id, nil, nil)
	w.WriteHeader(http.StatusNoContent)
}
