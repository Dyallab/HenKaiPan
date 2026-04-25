package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"aspm/internal/repository"
	"aspm/internal/tasks"

	"github.com/go-chi/chi/v5"
	"github.com/hibiken/asynq"
)

func (h *Handler) ListWebhooks(w http.ResponseWriter, r *http.Request) {
	webhooks, err := h.store.Webhooks.List(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list webhooks")
		return
	}
	writeJSON(w, http.StatusOK, webhooks)
}

func (h *Handler) CreateWebhook(w http.ResponseWriter, r *http.Request) {
	var body repository.WebhookCreate
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	if body.Label == "" {
		writeError(w, http.StatusBadRequest, "label required")
		return
	}
	if body.URL == "" {
		writeError(w, http.StatusBadRequest, "url required")
		return
	}
	body.DeliveryType = normalizeWebhookDeliveryType(body.DeliveryType)
	if body.DeliveryType == "" {
		writeError(w, http.StatusBadRequest, "invalid delivery_type")
		return
	}

	webhook, err := h.store.Webhooks.Create(r.Context(), body)
	if err != nil {
		slog.Error("failed to create webhook", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to create webhook: "+err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, webhook)
}

func (h *Handler) UpdateWebhook(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var body repository.WebhookUpdate
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	if body.DeliveryType != nil {
		normalized := normalizeWebhookDeliveryType(*body.DeliveryType)
		if normalized == "" {
			writeError(w, http.StatusBadRequest, "invalid delivery_type")
			return
		}
		body.DeliveryType = &normalized
	}

	webhook, err := h.store.Webhooks.Update(r.Context(), id, body)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to update webhook")
		return
	}
	writeJSON(w, http.StatusOK, webhook)
}

func (h *Handler) DeleteWebhook(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := h.store.Webhooks.Delete(r.Context(), id); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to delete webhook")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) TestWebhook(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	
	webhook, err := h.store.Webhooks.GetByID(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "webhook not found")
		return
	}

	payloadBytes, err := tasks.MarshalWebhookEvent("test", map[string]interface{}{
		"message":       "This is a test webhook delivery",
		"webhook_id":    webhook.ID,
		"webhook_label": webhook.Label,
	}, time.Now())
	if err != nil {
		slog.Error("failed to marshal test payload", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to create test payload")
		return
	}

	taskPayload, err := tasks.MarshalWebhookPayload(tasks.WebhookSendPayload{
		WebhookID: webhook.ID,
		EventType: "test",
		Payload:   payloadBytes,
	})
	if err != nil {
		slog.Error("failed to marshal task payload", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to create task")
		return
	}

	_, err = h.queue.EnqueueContext(r.Context(), asynq.NewTask(tasks.TypeWebhookSend, taskPayload), asynq.MaxRetry(5), asynq.Timeout(30*time.Second))
	if err != nil {
		slog.Error("failed to enqueue webhook test task", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to enqueue test")
		return
	}

	slog.Info("enqueued webhook test", "webhook_id", webhook.ID)
	writeJSON(w, http.StatusOK, map[string]string{"status": "queued", "message": "Test webhook queued for delivery"})
}

func normalizeWebhookDeliveryType(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "generic":
		return "generic"
	case "slack":
		return "slack"
	case "discord":
		return "discord"
	default:
		return ""
	}
}
