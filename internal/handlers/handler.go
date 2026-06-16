package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"aspm/internal/auth"
	"aspm/internal/cache"
	"aspm/internal/httperrors"
	"aspm/internal/repository"
	"aspm/internal/validation"

	"github.com/hibiken/asynq"
)

type Handler struct {
	store          repository.Stores
	queue          *asynq.Client
	frontendURL    string
	cookieSecure   bool
	cookieDomain   string
	cookieSameSite string
	aiRemediation  bool
	aiSummary      bool
	aiValidation   bool
	emailEnabled   bool
	webhookSecret  string
	FindingCache   *cache.Cache
	maxProjects    int
	maxUsers       int
	maxAIScans     int
}

func New(store repository.Stores, queue *asynq.Client, frontendURL string, cookieSecure bool, cookieDomain, cookieSameSite string, aiRemediation, aiSummary, aiValidation bool, emailEnabled bool, webhookSecret string, findingCache *cache.Cache, maxProjects, maxUsers, maxAIScans int) *Handler {
	return &Handler{store: store, queue: queue, frontendURL: frontendURL, cookieSecure: cookieSecure, cookieDomain: cookieDomain, cookieSameSite: cookieSameSite, aiRemediation: aiRemediation, aiSummary: aiSummary, aiValidation: aiValidation, emailEnabled: emailEnabled, webhookSecret: webhookSecret, FindingCache: findingCache, maxProjects: maxProjects, maxUsers: maxUsers, maxAIScans: maxAIScans}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, r *http.Request, status int, msg string) {
	code := statusCodeToCode(status)
	slog.ErrorContext(r.Context(), "http error",
		"code", code,
		"message", msg,
		"status", status,
		"path", r.URL.Path,
	)
	writeJSON(w, status, map[string]string{"code": code, "message": msg})
}

func statusCodeToCode(status int) string {
	switch status {
	case http.StatusBadRequest:
		return httperrors.ErrBadRequest
	case http.StatusUnauthorized:
		return httperrors.ErrUnauthorized
	case http.StatusForbidden:
		return httperrors.ErrForbidden
	case http.StatusNotFound:
		return httperrors.ErrNotFound
	case http.StatusConflict:
		return httperrors.ErrConflict
	case http.StatusInternalServerError:
		return httperrors.ErrInternal
	case http.StatusBadGateway:
		return httperrors.ErrInternal
	case http.StatusServiceUnavailable:
		return httperrors.ErrServiceUnavailable
	case http.StatusTooManyRequests:
		return httperrors.ErrRateLimited
	default:
		return httperrors.ErrInternal
	}
}

// writeHTTPError writes a standardized HTTP error response
func (h *Handler) writeHTTPError(w http.ResponseWriter, r *http.Request, httpErr *httperrors.HTTPError, statusCode int) {
	slog.ErrorContext(r.Context(), "http error",
		"code", httpErr.Code,
		"message", httpErr.Message,
		"details", httpErr.Details,
		"status", statusCode,
		"path", r.URL.Path,
	)
	writeJSON(w, statusCode, httpErr)
}

func (h *Handler) writeBadRequest(w http.ResponseWriter, r *http.Request, message string) {
	h.writeHTTPError(w, r, httperrors.New(httperrors.ErrBadRequest, message), http.StatusBadRequest)
}

func (h *Handler) writeUnauthorized(w http.ResponseWriter, r *http.Request) {
	h.writeHTTPError(w, r, httperrors.New(httperrors.ErrUnauthorized, "Invalid credentials"), http.StatusUnauthorized)
}

func (h *Handler) writeForbidden(w http.ResponseWriter, r *http.Request) {
	h.writeHTTPError(w, r, httperrors.New(httperrors.ErrForbidden, "Access denied"), http.StatusForbidden)
}

func (h *Handler) writeNotFound(w http.ResponseWriter, r *http.Request, resource string) {
	h.writeHTTPError(w, r, httperrors.New(httperrors.ErrNotFound, resource+" not found"), http.StatusNotFound)
}

func (h *Handler) writeInternal(w http.ResponseWriter, r *http.Request, err error, message string) {
	h.writeHTTPError(w, r, httperrors.Wrap(err, httperrors.ErrInternal, message), http.StatusInternalServerError)
}

func (h *Handler) writeLimitError(w http.ResponseWriter, r *http.Request, err error) {
	if httpErr, ok := err.(*httperrors.HTTPError); ok {
		h.writeHTTPError(w, r, httpErr, http.StatusForbidden)
	} else {
		h.writeInternal(w, r, err, "limit check failed")
	}
}

func (h *Handler) writeValidationErrors(w http.ResponseWriter, r *http.Request, validationErrs []validation.ValidationError) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	json.NewEncoder(w).Encode(map[string]any{
		"code":    httperrors.ErrValidation,
		"message": "Validation failed",
		"details": validationErrs,
	})
}

// auditLog helper: extracts claims and logs audit entry if user is authenticated
func (h *Handler) auditLog(r *http.Request, action, entityType, entityID string, oldValue, newValue any) {
	claims := auth.GetClaims(r)
	if claims == nil {
		return // Skip audit if no authenticated user
	}
	if err := h.store.Audit.Log(r.Context(), repository.AuditLogEntry{
		UserID:     claims.UserID,
		UserEmail:  claims.Sub,
		Action:     action,
		EntityType: entityType,
		EntityID:   entityID,
		OldValue:   oldValue,
		NewValue:   newValue,
	}); err != nil {
		slog.ErrorContext(r.Context(), "audit log failed", "action", action, "entity_type", entityType, "entity_id", entityID, "err", err)
	}
}

func (h *Handler) checkProjectLimit(ctx context.Context) error {
	if h.maxProjects < 0 {
		return nil
	}
	count, err := h.store.Apps.CountProjects(ctx)
	if err != nil {
		return fmt.Errorf("check project limit: %w", err)
	}
	if count >= h.maxProjects {
		return httperrors.New("limit_reached",
			fmt.Sprintf("Project limit reached (%d/%d). Contact sales to upgrade.", count, h.maxProjects))
	}
	return nil
}

func (h *Handler) checkUserLimit(ctx context.Context) error {
	if h.maxUsers < 0 {
		return nil
	}
	count, err := h.store.Users.Count(ctx)
	if err != nil {
		return fmt.Errorf("check user limit: %w", err)
	}
	if count >= h.maxUsers {
		return httperrors.New("limit_reached",
			fmt.Sprintf("User limit reached (%d/%d). Contact sales to upgrade.", count, h.maxUsers))
	}
	return nil
}

func (h *Handler) checkAIScanLimit(ctx context.Context) error {
	if h.maxAIScans < 0 {
		return nil
	}
	allowed, err := h.store.Usage.IncrementAIScan(ctx, monthKey(), h.maxAIScans)
	if err != nil {
		return fmt.Errorf("check ai scan limit: %w", err)
	}
	if !allowed {
		return httperrors.New("limit_reached",
			fmt.Sprintf("AI scan limit reached (%d/%d this month). Contact sales to upgrade.", h.maxAIScans, h.maxAIScans))
	}
	return nil
}

func monthKey() string {
	now := time.Now()
	return fmt.Sprintf("%d-%02d", now.Year(), now.Month())
}


