package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"aspm/internal/auth"
	"aspm/internal/repository"

	"github.com/hibiken/asynq"
)

type Handler struct {
	store        repository.Stores
	queue        *asynq.Client
	frontendURL  string
	cookieSecure bool
}

func New(store repository.Stores, queue *asynq.Client, frontendURL string, cookieSecure bool) *Handler {
	return &Handler{store: store, queue: queue, frontendURL: frontendURL, cookieSecure: cookieSecure}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
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


