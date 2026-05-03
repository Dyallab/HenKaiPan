package handlers

import (
	"log/slog"
	"net/http"

	"aspm/internal/tasks"

	"github.com/go-chi/chi/v5"
	"github.com/hibiken/asynq"
)

func (h *Handler) GetFindingCorrelations(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	if _, err := h.store.Findings.GetByID(r.Context(), id); err != nil {
		writeError(w, http.StatusNotFound, "finding not found")
		return
	}

	findings, err := h.store.Agents.GetCorrelatedFindings(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to get correlations")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"findings": findings,
		"total":    len(findings),
	})
}

// GetFindingAnalysis returns stored validation analysis for a finding.
func (h *Handler) GetFindingAnalysis(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	analysis, err := h.store.Agents.GetAnalysis(r.Context(), id, "validator")
	if err != nil {
		writeError(w, http.StatusNotFound, "no analysis found for this finding")
		return
	}
	writeJSON(w, http.StatusOK, analysis)
}

// AnalyzeFinding enqueues validation analysis for the finding.
func (h *Handler) AnalyzeFinding(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	// Verify finding exists
	if _, err := h.store.Findings.GetByID(r.Context(), id); err != nil {
		writeError(w, http.StatusNotFound, "finding not found")
		return
	}

	payload, err := tasks.MarshalFindingValidatePayload(tasks.FindingValidatePayload{FindingID: id})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	if _, err := h.queue.EnqueueContext(r.Context(), asynq.NewTask(tasks.TypeFindingValidate, payload)); err != nil {
		slog.Error("enqueue agent:validate", "finding_id", id, "err", err)
		writeError(w, http.StatusInternalServerError, "failed to enqueue analysis")
		return
	}

	writeJSON(w, http.StatusAccepted, map[string]string{
		"status":     "queued",
		"finding_id": id,
	})
}

// RequestFindingSummary enqueues AI summarization for the finding.
func (h *Handler) RequestFindingSummary(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	// Verify finding exists
	if _, err := h.store.Findings.GetByID(r.Context(), id); err != nil {
		writeError(w, http.StatusNotFound, "finding not found")
		return
	}

	payload, err := tasks.MarshalFindingSummarizePayload(tasks.FindingSummarizePayload{FindingID: id})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	if _, err := h.queue.EnqueueContext(r.Context(), asynq.NewTask(tasks.TypeFindingSummarize, payload)); err != nil {
		slog.Error("enqueue agent:summarize", "finding_id", id, "err", err)
		writeError(w, http.StatusInternalServerError, "failed to enqueue summary")
		return
	}

	writeJSON(w, http.StatusAccepted, map[string]string{
		"status":     "queued",
		"finding_id": id,
	})
}
