package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"aspm/internal/pagination"
	"aspm/internal/scanner"
	"aspm/internal/tasks"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/hibiken/asynq"
)

func (h *Handler) ListScans(w http.ResponseWriter, r *http.Request) {
	p := pagination.FromQuery(r.URL.Query())

	scans, total, err := h.store.Scans.List(r.Context(), p.Page, p.Limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list scans")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"scans": scans, "total": total})
}

func (h *Handler) CreateScan(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Target    string `json:"target"`
		Scanner   string `json:"scanner"`
		ProjectID string `json:"project_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Target == "" {
		writeError(w, http.StatusBadRequest, "target required")
		return
	}
	if req.Scanner == "" {
		req.Scanner = "semgrep"
	}

	var scannerNames []string
	if names, ok := scanner.ResolvePack(req.Scanner); ok {
		scannerNames = names
	} else if _, ok := scanner.Get(req.Scanner); !ok {
		writeError(w, http.StatusBadRequest, "unknown scanner: "+req.Scanner)
		return
	} else {
		scannerNames = []string{req.Scanner}
	}

	var projectID *string
	if req.ProjectID != "" {
		projectID = &req.ProjectID
	}
	batchID := uuid.NewString()

	var ids []string
	for _, name := range scannerNames {
		scanID, err := h.store.Scans.Insert(r.Context(), req.Target, name, batchID, projectID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to create scan")
			return
		}

		projectIDStr := ""
		if projectID != nil {
			projectIDStr = *projectID
		}
		payload, _ := tasks.MarshalScanPayload(tasks.ScanPayload{ScanID: scanID, ProjectID: projectIDStr, Target: req.Target, Scanner: name})
		h.queue.Enqueue(asynq.NewTask(tasks.TypeScanRun, payload), asynq.MaxRetry(3), asynq.Timeout(30*time.Minute))
		ids = append(ids, scanID)
	}

	writeJSON(w, http.StatusCreated, map[string]any{"ids": ids})
}

func (h *Handler) GetScan(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	s, err := h.store.Scans.Get(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "scan not found")
		return
	}
	writeJSON(w, http.StatusOK, s)
}

func (h *Handler) ListScannerPacks(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, scanner.Packs)
}

func (h *Handler) GetScanFindings(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	findings, err := h.store.Findings.GetByScanID(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to get findings")
		return
	}
	for i := range findings {
		h.normalizeFindingForDisplay(&findings[i])
	}
	writeJSON(w, http.StatusOK, findings)
}
