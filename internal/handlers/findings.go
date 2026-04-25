package handlers

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"aspm/internal/models"
	"aspm/internal/repository"
	"aspm/internal/tasks"

	"github.com/go-chi/chi/v5"
	"github.com/hibiken/asynq"
)

func (h *Handler) ListFindings(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	page, _ := strconv.Atoi(q.Get("page"))
	limit, _ := strconv.Atoi(q.Get("limit"))

	findings, total, err := h.store.Findings.List(r.Context(), repository.FindingFilter{
		Severities:     parseCSVParam(q.Get("severity")),
		Scanner:        q.Get("scanner"),
		Status:         q.Get("status"),
		Category:       q.Get("category"),
		CVESearch:      q.Get("cve_id"),
		Overdue:        q.Get("overdue") == "true",
		ShowSuppressed: q.Get("suppressed") == "true",
		Page:           page,
		Limit:          limit,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list findings")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"findings": findings, "total": total})
}

func (h *Handler) GetFinding(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	finding, err := h.store.Findings.GetByID(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "finding not found")
		return
	}
	h.maybeQueueFindingSummary(r, finding)

	h.normalizeFindingForDisplay(finding)
	if scan, err := h.store.Scans.Get(r.Context(), finding.ScanID); err == nil {
		h.enrichFindingCodeContext(r.Context(), scan.Target, finding)
	}

	writeJSON(w, http.StatusOK, finding)
}

func (h *Handler) maybeQueueFindingSummary(r *http.Request, finding *models.Finding) {
	if finding == nil || strings.TrimSpace(finding.Description) != "" || strings.TrimSpace(finding.AISummary) != "" {
		return
	}

	prepared, err := h.store.Findings.PrepareAISummary(r.Context(), finding.ID)
	if err != nil {
		slog.Warn("prepare finding summary failed", "finding_id", finding.ID, "err", err)
		return
	}
	if prepared == nil {
		return
	}
	if prepared.Summary != "" {
		finding.AISummary = prepared.Summary
	}
	if prepared.State != "" {
		finding.SummaryState = prepared.State
	}
	if !prepared.ShouldEnqueue {
		return
	}
	payload, err := tasks.MarshalAgentSummarizePayload(tasks.AgentSummarizePayload{FindingID: finding.ID})
	if err != nil {
		slog.Warn("marshal finding summary payload failed", "finding_id", finding.ID, "err", err)
		return
	}
	if _, err := h.queue.EnqueueContext(r.Context(), asynq.NewTask(tasks.TypeAgentSummarize, payload)); err != nil {
		slog.Warn("enqueue finding summary failed", "finding_id", finding.ID, "err", err)
	}
	finding.SummaryState = "pending"
}

func (h *Handler) UpdateFinding(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	var body struct {
		Status        *string `json:"status"`
		AssignedTo    *string `json:"assigned_to"`
		FalsePositive *bool   `json:"false_positive"`
		Notes         *string `json:"notes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}

	if body.Status != nil {
		valid := map[string]bool{
			"open": true, "in_review": true, "accepted_risk": true,
			"fixed": true, "verified": true,
		}
		if !valid[*body.Status] {
			writeError(w, http.StatusBadRequest, "invalid status")
			return
		}
	}

	f, err := h.store.Findings.Update(r.Context(), id, repository.FindingUpdate{
		Status:        body.Status,
		AssignedTo:    body.AssignedTo,
		FalsePositive: body.FalsePositive,
		Notes:         body.Notes,
	})
	if err != nil {
		writeError(w, http.StatusNotFound, "finding not found")
		return
	}
	writeJSON(w, http.StatusOK, f)
}

func (h *Handler) GetSLASummary(w http.ResponseWriter, r *http.Request) {
	s, err := h.store.Findings.GetSLASummary(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to get SLA summary")
		return
	}
	writeJSON(w, http.StatusOK, s)
}

func (h *Handler) ExportFindings(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	rows, err := h.store.Findings.ExportRows(r.Context(), repository.ExportFilter{
		Severities: parseCSVParam(q.Get("severity")),
		Scanner:    q.Get("scanner"),
		Status:     q.Get("status"),
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to export findings")
		return
	}

	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="findings-%s.csv"`, time.Now().Format("2006-01-02")))

	cw := csv.NewWriter(w)
	cw.Write([]string{"id", "scan_id", "scanner", "rule_id", "title", "description",
		"severity", "file_path", "line_start", "created_at",
		"status", "assigned_to", "false_positive", "notes", "resolved_at", "sla_deadline",
		"cve_id", "cwe_id", "confidence_score", "corroboration_count"})

	for _, f := range rows {
		fp := "false"
		if f.FalsePositive {
			fp = "true"
		}
		cw.Write([]string{
			f.ID, f.ScanID, f.Scanner, f.RuleID, f.Title, f.Description,
			f.Severity, f.FilePath, strconv.Itoa(f.LineStart), f.CreatedAt.Format(time.RFC3339),
			f.Status, derefStr(f.AssignedTo), fp, derefStr(f.Notes),
			fmtTime(f.ResolvedAt), fmtTime(f.SLADeadline),
			derefStr(f.CVEID), derefStr(f.CWEID), fmtFloat(f.ConfidenceScore), strconv.Itoa(f.CorroborationCount),
		})
	}
	cw.Flush()
}

func fmtFloat(v *float64) string {
	if v == nil {
		return ""
	}
	return strconv.FormatFloat(*v, 'f', 2, 64)
}

func parseCSVParam(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	values := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, part := range parts {
		value := strings.TrimSpace(part)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		values = append(values, value)
	}
	if len(values) == 0 {
		return nil
	}
	return values
}

func derefStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func fmtTime(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.Format(time.RFC3339)
}
