package handlers

import (
	"fmt"
	"net/http"
	"strconv"
	"time"
	"encoding/csv"
	"encoding/json"

	"aspm/internal/repository"

	"github.com/go-chi/chi/v5"
)

func (h *Handler) ListFindings(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	page, _ := strconv.Atoi(q.Get("page"))
	limit, _ := strconv.Atoi(q.Get("limit"))

	findings, total, err := h.store.Findings.List(r.Context(), repository.FindingFilter{
		Severity:       q.Get("severity"),
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
		Severity: q.Get("severity"),
		Scanner:  q.Get("scanner"),
		Status:   q.Get("status"),
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
		"cve_id", "cwe_id"})

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
			derefStr(f.CVEID), derefStr(f.CWEID),
		})
	}
	cw.Flush()
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
