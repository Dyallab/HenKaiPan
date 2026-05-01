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
		Target  string `json:"target"`
		Scanner string `json:"scanner"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Target == "" {
		writeError(w, http.StatusBadRequest, "target required")
		return
	}
	if req.Scanner == "" {
		req.Scanner = "semgrep"
	}

	var scannerNames []string
	if req.Scanner == "all" {
		scannerNames = scanner.GitScannerNames()
	} else if req.Scanner == "sast" {
		scannerNames = []string{"semgrep", "gosec"}
	} else if req.Scanner == "sca" {
		scannerNames = []string{"trivy", "grype", "osv-scanner"}
	} else if req.Scanner == "secrets" {
		scannerNames = []string{"trufflehog", "gitleaks"}
	} else if req.Scanner == "iac" {
		scannerNames = []string{"checkov", "tfsec", "kics"}
	} else if req.Scanner == "containers" {
		scannerNames = []string{"trivy-image", "grype-image"}
	} else {
		if _, ok := scanner.Get(req.Scanner); !ok {
			writeError(w, http.StatusBadRequest, "unknown scanner: "+req.Scanner)
			return
		}
		scannerNames = []string{req.Scanner}
	}

	repoID, _ := h.store.Scans.FindRepoIDByTarget(r.Context(), req.Target)
	batchID := uuid.NewString()

	var ids []string
	for _, name := range scannerNames {
		scanID, err := h.store.Scans.Insert(r.Context(), req.Target, name, batchID, repoID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to create scan")
			return
		}

		repoIDStr := ""
		if repoID != nil {
			repoIDStr = *repoID
		}
		payload, _ := tasks.MarshalScanPayload(tasks.ScanPayload{ScanID: scanID, RepoID: repoIDStr, Target: req.Target, Scanner: name})
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
