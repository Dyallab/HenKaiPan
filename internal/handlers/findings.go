package handlers

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"aspm/internal/events"
	"aspm/internal/models"
	"aspm/internal/pagination"
	"aspm/internal/repository"
	"aspm/internal/tasks"
	"aspm/internal/validation"

	"github.com/go-chi/chi/v5"
	"github.com/hibiken/asynq"
)

func (h *Handler) ListFindings(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	p := pagination.FromQuery(q)

	findings, total, err := h.store.Findings.List(r.Context(), repository.FindingFilter{
		Severities:     parseCSVParam(q.Get("severity")),
		Scanner:        q.Get("scanner"),
		Status:         q.Get("status"),
		Category:       q.Get("category"),
		CVESearch:      q.Get("cve_id"),
		Overdue:        q.Get("overdue") == "true",
		ShowSuppressed: q.Get("suppressed") == "true",
		Page:           p.Page,
		Limit:          p.Limit,
		FilePath:       q.Get("file_path"),
		SortBy:         q.Get("sort_by"),
	})
	if err != nil {
		h.writeInternal(w, r, err, "failed to list findings")
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
	h.normalizeFindingForDisplay(finding)
	if scan, err := h.store.Scans.Get(r.Context(), finding.ScanID); err == nil {
		h.enrichFindingCodeContext(r.Context(), scan.Target, finding)
	}

	writeJSON(w, http.StatusOK, finding)
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
		h.writeBadRequest(w, r, "invalid body")
		return
	}

	if body.Status != nil {
		if !validation.IsValid(validation.FindingStatuses, *body.Status) {
			h.writeBadRequest(w, r, "invalid status")
			return
		}
	}

	// Validate assigned_to if provided (empty string means remove owner)
	if body.AssignedTo != nil {
		owner := *body.AssignedTo
		if owner != "" {
			// Validate that owner exists as username or team name
			valid, err := h.validateOwner(r.Context(), owner)
			if err != nil {
				slog.Error("validate owner failed", "owner", owner, "err", err)
				h.writeInternal(w, r, err, "failed to validate owner")
				return
			}
			if !valid {
				h.writeBadRequest(w, r, fmt.Sprintf("owner '%s' not found. Must be a valid username or team name.", owner))
				return
			}
		}
	}

	// Get old value for audit trail
	oldFinding, _ := h.store.Findings.GetByID(r.Context(), id)
	oldOwner := oldFinding.AssignedTo

	f, err := h.store.Findings.Update(r.Context(), id, repository.FindingUpdate{
		Status:        body.Status,
		AssignedTo:    body.AssignedTo,
		FalsePositive: body.FalsePositive,
		Notes:         body.Notes,
	})
	if err != nil {
		h.writeNotFound(w, r, "finding")
		return
	}

	h.auditLog(r, "finding.update", "finding", id, oldFinding, f)

	// Send notification if owner was assigned (and changed)
	if body.AssignedTo != nil && *body.AssignedTo != "" && (oldOwner == nil || *body.AssignedTo != *oldOwner) {
		h.notifyOwnerAssignment(r.Context(), f.ID, f.Title, *body.AssignedTo)
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

func (h *Handler) GetUniqueFiles(w http.ResponseWriter, r *http.Request) {
	files, err := h.store.Findings.ListUniqueFiles(r.Context());
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list files")
		return
	}
	writeJSON(w, http.StatusOK, files)
}

func (h *Handler) BulkUpdateFindings(w http.ResponseWriter, r *http.Request) {
	var body struct {
		FindingIDs   []string `json:"finding_ids"`
		Status       *string  `json:"status,omitempty"`
		AssignedTo   *string  `json:"assigned_to,omitempty"`
		FalsePositive *bool   `json:"false_positive,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if len(body.FindingIDs) == 0 {
		writeError(w, http.StatusBadRequest, "finding_ids required")
		return
	}

	updated := 0
	for _, id := range body.FindingIDs {
		upd := repository.FindingUpdate{}
		if body.Status != nil {
			upd.Status = body.Status
		}
		if body.AssignedTo != nil {
			upd.AssignedTo = body.AssignedTo
		}
		if body.FalsePositive != nil {
			upd.FalsePositive = body.FalsePositive
		}
		if _, err := h.store.Findings.Update(r.Context(), id, upd); err == nil {
			updated++
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{"updated": updated})
}

// validateOwner checks if the given owner string matches a username or team name
func (h *Handler) validateOwner(ctx context.Context, owner string) (bool, error) {
	// First check if it's a username
	users, err := h.store.Users.List(ctx)
	if err != nil {
		return false, fmt.Errorf("list users: %w", err)
	}
	for _, u := range users {
		if u.Username == owner || u.Email == owner {
			return true, nil
		}
	}

	// Then check if it's a team name
	teams, err := h.store.Teams.List(ctx)
	if err != nil {
		return false, fmt.Errorf("list teams: %w", err)
	}
	for _, t := range teams {
		if t.Name == owner {
			return true, nil
		}
	}

	return false, nil
}

// notifyOwnerAssignment creates a notification and sends email to the assigned owner
func (h *Handler) notifyOwnerAssignment(ctx context.Context, findingID, findingTitle, owner string) {
	// Get user by username or email
	users, err := h.store.Users.List(ctx)
	if err != nil {
		slog.Error("notify owner: list users failed", "err", err)
		return
	}

	var targetUser *models.User
	for _, u := range users {
		if u.Username == owner || u.Email == owner {
			targetUser = &u
			break
		}
	}

	// If owner is a team or user not found, skip notification
	if targetUser == nil {
		return
	}

	// Create web notification
	notif, err := h.store.Notifications.Create(ctx, repository.NotificationCreate{
		UserID:     targetUser.ID,
		Title:      "New Finding Assigned",
		Message:    "You have been assigned as owner of finding: " + findingTitle,
		Type:       "finding_assignment",
		EntityType: ptr("finding"),
		EntityID:   &findingID,
	})
	if err != nil {
		slog.Error("create notification failed", "err", err)
	} else {
		entityType := ""
		if notif.EntityType != nil {
			entityType = *notif.EntityType
		}
		entityID := ""
		if notif.EntityID != nil {
			entityID = *notif.EntityID
		}
		events.NewNotificationCreated(
			notif.ID, targetUser.ID, notif.Title, notif.Type,
			entityType, entityID,
		).Publish()
	}

	// Queue email notification
	payload, err := tasks.MarshalEmailSendPayload(tasks.EmailSendPayload{
		Subject: "Finding assigned to you: " + findingTitle,
		Body: "Hi " + targetUser.Username + ",\n\nYou have been assigned as the owner of the following finding:\n\nTitle: " + findingTitle + "\nFinding ID: " + findingID + "\n\nPlease review it in the dashboard.\n\nThanks,\nHenKaiPan Team",
		To:   []string{targetUser.Email},
	})
	if err != nil {
		slog.Error("marshal email payload failed", "err", err)
		return
	}
	if _, err := h.queue.EnqueueContext(ctx, asynq.NewTask(tasks.TypeEmailSend, payload), asynq.MaxRetry(5), asynq.Timeout(30*time.Second)); err != nil {
		slog.Error("enqueue email failed", "err", err)
	}
}

func ptr[T any](v T) *T {
	return &v
}
