package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"aspm/internal/auth"
	"aspm/internal/httperrors"
	"aspm/internal/license"
	"aspm/internal/repository"

	"github.com/hibiken/asynq"
)

type Handler struct {
	store        repository.Stores
	queue        *asynq.Client
	frontendURL  string
	cookieSecure bool
	license      *license.Service
}

func New(store repository.Stores, queue *asynq.Client, frontendURL string, cookieSecure bool, lic *license.Service) *Handler {
	return &Handler{store: store, queue: queue, frontendURL: frontendURL, cookieSecure: cookieSecure, license: lic}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
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

func (h *Handler) writeLicenseRequired(w http.ResponseWriter, r *http.Request, feature string) {
	h.writeHTTPError(w, r,
		httperrors.New(httperrors.ErrLicenseRequired, "License required for this feature").
			WithMetadata("feature", feature),
		http.StatusPaymentRequired)
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


