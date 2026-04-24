package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"

	"aspm/internal/scanner"
	"aspm/internal/tasks"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/hibiken/asynq"
)

func (h *Handler) ListScans(w http.ResponseWriter, r *http.Request) {
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))

	scans, total, err := h.store.Scans.List(r.Context(), page, limit)
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

		payload, _ := tasks.MarshalPayload(tasks.ScanPayload{ScanID: scanID, Target: req.Target, Scanner: name})
		h.queue.Enqueue(asynq.NewTask(tasks.TypeScanRun, payload))
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
	writeJSON(w, http.StatusOK, findings)
}
