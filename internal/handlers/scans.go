package handlers

import (
	"encoding/json"
	"log/slog"
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

func resolveScanner(reqScanner string) ([]string, bool) {
	if names, ok := scanner.ResolvePack(reqScanner); ok {
		return names, true
	}
	if _, ok := scanner.Get(reqScanner); ok {
		return []string{reqScanner}, true
	}
	return nil, false
}

func (h *Handler) CreateScan(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Target    string `json:"target"`
		Scanner   string `json:"scanner"`
		ProjectID string `json:"project_id"`
		AppID     string `json:"app_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}

	if req.AppID != "" {
		h.createAppScans(w, r, req.AppID, req.Scanner)
		return
	}

	if req.Target == "" {
		writeError(w, http.StatusBadRequest, "target or app_id required")
		return
	}
	if req.Scanner == "" {
		req.Scanner = "semgrep"
	}

	scannerNames, ok := resolveScanner(req.Scanner)
	if !ok {
		writeError(w, http.StatusBadRequest, "unknown scanner: "+req.Scanner)
		return
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

func (h *Handler) createAppScans(w http.ResponseWriter, r *http.Request, appID, scannerName string) {
	app, err := h.store.Apps.Get(r.Context(), appID)
	if err != nil {
		writeError(w, http.StatusNotFound, "app not found")
		return
	}

	scannerNames, ok := scanner.ResolvePack(scannerName)
	if !ok {
		if _, ok := scanner.Get(scannerName); !ok {
			writeError(w, http.StatusBadRequest, "unknown scanner: "+scannerName)
			return
		}
		scannerNames = []string{scannerName}
	}

	batchID := uuid.NewString()
	var allIDs []string

	for _, project := range app.Projects {
		if project.RepoURL == nil || *project.RepoURL == "" {
			slog.Warn("project has no repo_url, skipping", "project_id", project.ID, "project_name", project.Name)
			continue
		}
		target := *project.RepoURL

		for _, sName := range scannerNames {
			scanID, err := h.store.Scans.Insert(r.Context(), target, sName, batchID, &project.ID)
			if err != nil {
				slog.Error("failed to insert scan for project", "project_id", project.ID, "scanner", sName, "err", err)
				continue
			}

			payload, _ := tasks.MarshalScanPayload(tasks.ScanPayload{
				ScanID:    scanID,
				ProjectID: project.ID,
				Target:    target,
				Scanner:   sName,
			})
			h.queue.Enqueue(asynq.NewTask(tasks.TypeScanRun, payload), asynq.MaxRetry(3), asynq.Timeout(30*time.Minute))
			allIDs = append(allIDs, scanID)
		}
	}

	if len(allIDs) == 0 {
		writeError(w, http.StatusInternalServerError, "no scans created — projects may be missing repo URLs")
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{"ids": allIDs})
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
