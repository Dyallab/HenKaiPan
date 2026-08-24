package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"aspm/internal/auth"
	"aspm/internal/events"
	"aspm/internal/models"
	"aspm/internal/repository"
	"aspm/internal/tasks"

	"github.com/go-chi/chi/v5"
	"github.com/hibiken/asynq"
)

// mentionPattern matches @username mentions: 2-39 word characters (letters,
// digits, underscore), preceded by start-of-string or whitespace so that email
// addresses (e.g. foo@bar.com) are not treated as mentions. Trailing
// punctuation is excluded because it does not match \w.
var mentionPattern = regexp.MustCompile(`(?:^|\s)@(\w{2,39})`)

// extractMentions returns the unique usernames mentioned in a comment.
func extractMentions(content string) []string {
	matches := mentionPattern.FindAllStringSubmatch(content, -1)
	if len(matches) == 0 {
		return nil
	}
	seen := make([]string, 0, len(matches))
	for _, m := range matches {
		username := m[1]
		dup := false
		for _, s := range seen {
			// Usernames are case-sensitive (UNIQUE in the schema), so only
			// exact repeats are duplicates.
			if s == username {
				dup = true
				break
			}
		}
		if !dup {
			seen = append(seen, username)
		}
	}
	return seen
}

func (h *Handler) GetFindingComments(w http.ResponseWriter, r *http.Request) {
	findingID := chi.URLParam(r, "findingID")

	comments, err := h.store.Apps.GetFindingComments(r.Context(), findingID)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "failed to get comments")
		return
	}
	writeJSON(w, http.StatusOK, comments)
}

func (h *Handler) CreateFindingComment(w http.ResponseWriter, r *http.Request) {
	findingID := chi.URLParam(r, "findingID")

	claims := auth.GetClaims(r)
	if claims == nil {
		writeError(w, r, http.StatusUnauthorized, "unauthorized")
		return
	}

	var body struct {
		Content string `json:"content"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Content == "" {
		writeError(w, r, http.StatusBadRequest, "content required")
		return
	}

	comment, err := h.store.Apps.CreateFindingComment(r.Context(), repository.CommentCreate{
		FindingID: findingID,
		UserID:    claims.UserID,
		Content:   body.Content,
	})
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "failed to create comment")
		return
	}
	writeJSON(w, http.StatusCreated, comment)

	h.notifyMentionedUsers(r.Context(), findingID, claims.UserID, claims.Sub, body.Content)
}

func (h *Handler) DeleteFindingComment(w http.ResponseWriter, r *http.Request) {
	commentID, err := strconv.ParseInt(chi.URLParam(r, "commentID"), 10, 64)
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid comment ID")
		return
	}

	if err := h.store.Apps.DeleteFindingComment(r.Context(), commentID); err != nil {
		writeError(w, r, http.StatusInternalServerError, "failed to delete comment")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// notifyMentionedUsers resolves @username mentions in a comment and sends an
// in-app + email notification to each mentioned user except the author.
// Failures are logged but never fail the comment creation.
func (h *Handler) notifyMentionedUsers(ctx context.Context, findingID, authorID, authorUsername, content string) {
	mentions := extractMentions(content)
	if len(mentions) == 0 {
		return
	}

	finding, err := h.store.Findings.GetByID(ctx, findingID)
	if err != nil {
		slog.ErrorContext(ctx, "notify mentioned users: get finding failed", "finding_id", findingID, "err", err)
		return
	}
	link := ""
	if h.frontendURL != "" {
		link = strings.TrimRight(h.frontendURL, "/") + "/dashboard/findings/detail?id=" + url.QueryEscape(findingID)
	}

	for _, username := range mentions {
		user, err := h.store.Users.GetByUsername(ctx, username)
		if err != nil {
			// Unresolved mentions are ignored per issue acceptance criteria.
			slog.WarnContext(ctx, "mention not resolved", "username", username, "finding_id", findingID)
			continue
		}
		if user.ID == authorID || !user.IsActive {
			continue
		}

		h.notifyOneMentionedUser(ctx, user, authorUsername, finding.Title, content, link, findingID)
	}
}

func (h *Handler) notifyOneMentionedUser(ctx context.Context, user *models.User, authorUsername, findingTitle, commentContent, link, findingID string) {
	message := fmt.Sprintf("%s mentioned you in a comment on finding: %s", authorUsername, findingTitle)
	notif, err := h.store.Notifications.Create(ctx, repository.NotificationCreate{
		UserID:     user.ID,
		Title:      "You were mentioned in a comment",
		Message:    message,
		Type:       "comment_mention",
		EntityType: ptr("finding"),
		EntityID:   &findingID,
	})
	if err != nil {
		slog.ErrorContext(ctx, "create mention notification failed", "user_id", user.ID, "err", err)
	} else {
		entityType := ""
		if notif.EntityType != nil {
			entityType = *notif.EntityType
		}
		entityID := ""
		if notif.EntityID != nil {
			entityID = *notif.EntityID
		}
		events.Publish(events.NewNotificationCreated(
			notif.ID, user.ID, notif.Title, notif.Type,
			entityType, entityID, notif.AISummary,
		))
	}

	if h.emailEnabled {
		payload, err := tasks.MarshalEmailSendPayload(tasks.EmailSendPayload{
			Subject: "[HenKaiPan] You were mentioned in a comment",
			Body:    buildMentionEmailBody(user.Username, authorUsername, findingTitle, commentContent, link),
			To:      []string{user.Email},
		})
		if err != nil {
			slog.ErrorContext(ctx, "marshal mention email payload failed", "err", err)
			return
		}
		if _, err := h.queue.EnqueueContext(ctx,
			asynq.NewTask(tasks.TypeEmailSend, payload),
			asynq.MaxRetry(5),
			asynq.Timeout(30*time.Second),
		); err != nil {
			slog.ErrorContext(ctx, "enqueue mention email failed", "user_id", user.ID, "err", err)
		}
	}
}

func buildMentionEmailBody(username, authorUsername, findingTitle, commentContent, link string) string {
	var b strings.Builder
	b.WriteString("Hi " + username + ",\n\n")
	b.WriteString(authorUsername + " mentioned you in a comment on finding \"" + findingTitle + "\":\n\n")
	b.WriteString("---\n" + commentContent + "\n---\n\n")
	if link != "" {
		b.WriteString("View it here: " + link + "\n\n")
	}
	b.WriteString("Thanks,\nHenKaiPan Team")
	return b.String()
}
