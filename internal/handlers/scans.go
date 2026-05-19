package handlers

import (
	"context"
	"encoding/json"
	"fmt"
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
		writeError(w, r, http.StatusInternalServerError, "failed to list scans")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"scans": scans, "total": total})
}

// ── Shared scan helpers ────────────────────────────────────────────────────

// resolveScanners resolves a list of scanner names (which may include pack
// aliases like "all", "sast", etc.) into concrete scanner names.
func resolveScanners(names []string) ([]string, error) {
	var resolved []string
	for _, s := range names {
		if packNames, ok := scanner.ResolvePack(s); ok {
			resolved = append(resolved, packNames...)
		} else if _, ok := scanner.Get(s); ok {
			resolved = append(resolved, s)
		} else {
			return nil, fmt.Errorf("unknown scanner: %s", s)
		}
	}
	return resolved, nil
}

// createScanRecords inserts a row in the scans table and enqueues a scan-run
// task for each scanner name. If batchID is empty, a new one is generated.
// Returns the created scan IDs, the batch ID used, and an error.
func (h *Handler) createScanRecords(ctx context.Context, target string, scannerNames []string, projectID *string, batchID string) (ids []string, outBatchID string, err error) {
	if batchID == "" {
		batchID = uuid.NewString()
	}
	for _, name := range scannerNames {
		scanID, err := h.store.Scans.Insert(ctx, target, name, batchID, projectID)
		if err != nil {
			return nil, "", fmt.Errorf("insert scan: %w", err)
		}

		pid := ""
		if projectID != nil {
			pid = *projectID
		}
		payload, _ := tasks.MarshalScanPayload(tasks.ScanPayload{
			ScanID:    scanID,
			ProjectID: pid,
			Target:    target,
			Scanner:   name,
		})
		h.queue.Enqueue(
			asynq.NewTask(tasks.TypeScanRun, payload),
			asynq.MaxRetry(3),
			asynq.Timeout(30*time.Minute),
		)
		ids = append(ids, scanID)
	}
	return ids, batchID, nil
}

// ── Scan handlers ──────────────────────────────────────────────────────────

func (h *Handler) CreateScan(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Target    string `json:"target"`
		Scanner   string `json:"scanner"`
		ProjectID string `json:"project_id"`
		AppID     string `json:"app_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid body")
		return
	}

	if req.AppID != "" {
		h.createAppScans(w, r, req.AppID, req.Scanner)
		return
	}

	if req.Target == "" {
		writeError(w, r, http.StatusBadRequest, "target or app_id required")
		return
	}
	if req.Scanner == "" {
		req.Scanner = "semgrep"
	}

	scannerNames, err := resolveScanners([]string{req.Scanner})
	if err != nil {
		writeError(w, r, http.StatusBadRequest, err.Error())
		return
	}

	var projectID *string
	if req.ProjectID != "" {
		projectID = &req.ProjectID
	}

	ids, batchID, err := h.createScanRecords(r.Context(), req.Target, scannerNames, projectID, "")
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "failed to create scans")
		return
	}
	h.auditLog(r, "scan.create", "scan", batchID, nil, map[string]any{"target": req.Target, "scanners": scannerNames, "ids": ids})
	writeJSON(w, http.StatusCreated, map[string]any{"ids": ids})
}

func (h *Handler) createAppScans(w http.ResponseWriter, r *http.Request, appID, scannerName string) {
	app, err := h.store.Apps.Get(r.Context(), appID)
	if err != nil {
		writeError(w, r, http.StatusNotFound, "app not found")
		return
	}

	scannerNames, err := resolveScanners([]string{scannerName})
	if err != nil {
		writeError(w, r, http.StatusBadRequest, err.Error())
		return
	}

	batchID := uuid.NewString()
	var allIDs []string

	for _, project := range app.Projects {
		if project.RepoURL == nil || *project.RepoURL == "" {
			slog.Warn("project has no repo_url, skipping", "project_id", project.ID, "project_name", project.Name)
			continue
		}
		ids, _, err := h.createScanRecords(r.Context(), *project.RepoURL, scannerNames, &project.ID, batchID)
		if err != nil {
			slog.Error("failed to create scans for project", "project_id", project.ID, "err", err)
			continue
		}
		allIDs = append(allIDs, ids...)
	}

	if len(allIDs) == 0 {
		writeError(w, r, http.StatusInternalServerError, "no scans created — projects may be missing repo URLs")
		return
	}

	h.auditLog(r, "scan.create", "scan", batchID, nil, map[string]any{"app_id": appID, "app_name": app.Name, "scanners": scannerNames, "count": len(allIDs)})
	writeJSON(w, http.StatusCreated, map[string]any{"ids": allIDs})
}

func (h *Handler) GetScan(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	s, err := h.store.Scans.Get(r.Context(), id)
	if err != nil {
		writeError(w, r, http.StatusNotFound, "scan not found")
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
		writeError(w, r, http.StatusInternalServerError, "failed to get findings")
		return
	}
	for i := range findings {
		h.normalizeFindingForDisplay(&findings[i])
	}
	writeJSON(w, http.StatusOK, findings)
}
