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

	"aspm/internal/auth"
	"aspm/internal/datascope"
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
	claims := auth.GetClaims(r)

	var userID *string
	if claims != nil && claims.Role != "admin" {
		userID = &claims.UserID
	}

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
		UserID:         userID,
	})
	if err != nil {
		h.writeInternal(w, r, err, "failed to list findings")
		return
	}
	for i := range findings {
		h.normalizeFindingForDisplay(&findings[i])
	}
	writeJSON(w, http.StatusOK, map[string]any{"findings": findings, "total": total})
}

func (h *Handler) GetFinding(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	finding, err := h.store.Findings.GetByID(r.Context(), id)
	if err != nil {
		writeError(w, r, http.StatusNotFound, "finding not found")
		return
	}
	h.normalizeFindingForDisplay(finding)

	writeJSON(w, http.StatusOK, finding)
}

func (h *Handler) UpdateFinding(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	var req validation.UpdateFindingRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeBadRequest(w, r, "invalid body")
		return
	}

	if validationErrs := validation.ValidateStruct(req); validationErrs != nil {
		h.writeValidationErrors(w, r, validationErrs)
		return
	}

	// Get old value for audit trail
	oldFinding, _ := h.store.Findings.GetByID(r.Context(), id)

	f, err := h.store.Findings.Update(r.Context(), id, repository.FindingUpdate{
		Status:     &req.Status,
		AssignedTo: req.AssignedTo,
		Notes:      &req.Notes,
	})
	if err != nil {
		h.writeNotFound(w, r, "finding")
		return
	}

	h.auditLog(r, "finding.update", "finding", id, oldFinding, f)

	h.normalizeFindingForDisplay(f)

	if h.FindingCache != nil {
		if cerr := h.FindingCache.Del(r.Context(), id+":detail"); cerr != nil {
			slog.Warn("update finding: failed to invalidate cache", "finding_id", id, "err", cerr)
		}
	}

	if req.AssignedTo != nil && strings.TrimSpace(*req.AssignedTo) != "" {
		oldOwner := derefStr(oldFinding.AssignedTo)
		newOwner := strings.TrimSpace(*req.AssignedTo)
		if oldOwner != newOwner {
			go h.notifyOwnerAssignment(context.Background(), id, f.Title, newOwner)
		}
	}

	writeJSON(w, http.StatusOK, f)
}

func (h *Handler) GetSLASummary(w http.ResponseWriter, r *http.Request) {
	claims := auth.GetClaims(r)
	scope := datascope.Admin()
	if claims != nil && claims.Role != "admin" {
		scope = datascope.ForUser(claims.UserID)
	}

	s, err := h.store.Findings.GetSLASummary(r.Context(), scope)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "failed to get SLA summary")
		return
	}
	writeJSON(w, http.StatusOK, s)
}

func (h *Handler) ExportFindings(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	claims := auth.GetClaims(r)
	scope := datascope.Admin()
	if claims != nil && claims.Role != "admin" {
		scope = datascope.ForUser(claims.UserID)
	}

	rows, err := h.store.Findings.ExportRows(r.Context(), repository.ExportFilter{
		Severities: parseCSVParam(q.Get("severity")),
		Scanner:    q.Get("scanner"),
		Status:     q.Get("status"),
	}, scope)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "failed to export findings")
		return
	}

	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="findings-%s.csv"`, time.Now().Format("2006-01-02")))

	cw := csv.NewWriter(w)
	cw.Write([]string{"id", "scan_id", "scanner", "rule_id", "title", "description",
		"severity", "file_path", "line_start", "created_at",
		"status", "assigned_to", "false_positive", "notes", "resolved_at", "sla_deadline",
		"cve_id", "cwe_id"})

	for i := range rows {
		h.normalizeFindingForDisplay(&rows[i])
	}
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
	claims := auth.GetClaims(r)
	scope := datascope.Admin()
	if claims != nil && claims.Role != "admin" {
		scope = datascope.ForUser(claims.UserID)
	}

	files, err := h.store.Findings.ListUniqueFiles(r.Context(), scope);
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "failed to list files")
		return
	}
	writeJSON(w, http.StatusOK, files)
}

func (h *Handler) BulkUpdateFindings(w http.ResponseWriter, r *http.Request) {
	var req validation.BulkUpdateFindingsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid request body")
		return
	}

	if validationErrs := validation.ValidateStruct(req); validationErrs != nil {
		h.writeValidationErrors(w, r, validationErrs)
		return
	}

	upd := repository.FindingUpdate{}
	if req.Status != "" {
		upd.Status = &req.Status
	}
	if req.AssignedTo != nil {
		upd.AssignedTo = req.AssignedTo
	}
	if req.Notes != nil {
		upd.Notes = req.Notes
	}

	if upd.Status == nil && upd.AssignedTo == nil && upd.Notes == nil {
		writeError(w, r, http.StatusBadRequest, "at least one field (status, assigned_to, notes) is required")
		return
	}

	updated := 0
	for _, id := range req.IDs {
		f, err := h.store.Findings.Update(r.Context(), id, upd)
		if err != nil {
			slog.Debug("bulk update: failed to update finding", "finding_id", id, "err", err)
			continue
		}

		h.auditLog(r, "finding.bulk_update", "finding", id, nil, f)

		if upd.AssignedTo != nil && *upd.AssignedTo != "" {
			oldFinding, oldErr := h.store.Findings.GetByID(r.Context(), id)
			if oldErr == nil {
				oldOwner := derefStr(oldFinding.AssignedTo)
				newOwner := *upd.AssignedTo
				if oldOwner != newOwner {
					go h.notifyOwnerAssignment(context.Background(), id, f.Title, newOwner)
				}
			}
		}

		if h.FindingCache != nil {
			if cerr := h.FindingCache.Del(r.Context(), id+":detail"); cerr != nil {
				slog.Warn("bulk update: failed to invalidate cache", "finding_id", id, "err", cerr)
			}
		}
		updated++
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

	finding, fErr := h.store.Findings.GetByID(ctx, findingID)
	aiSummary := ""
	if fErr == nil {
		aiSummary = finding.AISummary
	}

	// Create web notification
	notif, err := h.store.Notifications.Create(ctx, repository.NotificationCreate{
		UserID:     targetUser.ID,
		Title:      "New Finding Assigned",
		Message:    "You have been assigned as owner of finding: " + findingTitle,
		Type:       "finding_assignment",
		EntityType: ptr("finding"),
		EntityID:   &findingID,
		AISummary:  aiSummary,
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
			entityType, entityID, notif.AISummary,
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
