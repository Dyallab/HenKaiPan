package handlers

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"aspm/internal/repository"
	"aspm/internal/tasks"
	"aspm/internal/validation"

	"github.com/go-chi/chi/v5"
	"github.com/hibiken/asynq"
)

func (h *Handler) ListWebhooks(w http.ResponseWriter, r *http.Request) {
	webhooks, err := h.store.Webhooks.List(r.Context())
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "failed to list webhooks")
		return
	}
	writeJSON(w, http.StatusOK, webhooks)
}

func (h *Handler) CreateWebhook(w http.ResponseWriter, r *http.Request) {
	var body repository.WebhookCreate
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid body")
		return
	}
	if body.Label == "" {
		writeError(w, r, http.StatusBadRequest, "label required")
		return
	}
	if body.URL == "" {
		writeError(w, r, http.StatusBadRequest, "url required")
		return
	}
	if err := validateWebhookURL(body.URL); err != nil {
		writeError(w, r, http.StatusBadRequest, err.Error())
		return
	}
	body.DeliveryType = validation.NormalizeWebhookDeliveryType(body.DeliveryType)
	if body.DeliveryType == "" {
		writeError(w, r, http.StatusBadRequest, "invalid delivery_type")
		return
	}

	webhook, err := h.store.Webhooks.Create(r.Context(), body)
	if err != nil {
		slog.Error("failed to create webhook", "err", err)
		writeError(w, r, http.StatusInternalServerError, "failed to create webhook")
		return
	}
	h.auditLog(r, "webhook.create", "webhook", webhook.ID, nil, webhook)
	writeJSON(w, http.StatusCreated, webhook)
}

func (h *Handler) UpdateWebhook(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var body repository.WebhookUpdate
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid body")
		return
	}
	if body.DeliveryType != nil {
		normalized := validation.NormalizeWebhookDeliveryType(*body.DeliveryType)
		if normalized == "" {
			writeError(w, r, http.StatusBadRequest, "invalid delivery_type")
			return
		}
		body.DeliveryType = &normalized
	}
	if body.URL != nil {
		if err := validateWebhookURL(*body.URL); err != nil {
			writeError(w, r, http.StatusBadRequest, err.Error())
			return
		}
	}

	webhook, err := h.store.Webhooks.Update(r.Context(), id, body)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "failed to update webhook")
		return
	}
	h.auditLog(r, "webhook.update", "webhook", id, nil, webhook)
	writeJSON(w, http.StatusOK, webhook)
}

func validateWebhookURL(raw string) error {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return fmt.Errorf("webhook url must be absolute")
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return fmt.Errorf("webhook url must use http or https")
	}
	if parsed.User != nil {
		return fmt.Errorf("webhook url must not contain credentials")
	}
	host := strings.ToLower(parsed.Hostname())
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return fmt.Errorf("webhook url must not target localhost")
	}
	if ip := net.ParseIP(host); ip != nil && !isPublicWebhookIP(ip) {
		return fmt.Errorf("webhook url must target a public address")
	}
	return nil
}

func isPublicWebhookIP(ip net.IP) bool {
	return !(ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified())
}

func (h *Handler) DeleteWebhook(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	oldWebhook, _ := h.store.Webhooks.GetByID(r.Context(), id)
	if err := h.store.Webhooks.Delete(r.Context(), id); err != nil {
		writeError(w, r, http.StatusInternalServerError, "failed to delete webhook")
		return
	}
	h.auditLog(r, "webhook.delete", "webhook", id, oldWebhook, nil)
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) TestWebhook(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	webhook, err := h.store.Webhooks.GetByID(r.Context(), id)
	if err != nil {
		writeError(w, r, http.StatusNotFound, "webhook not found")
		return
	}

	payloadBytes, err := tasks.MarshalWebhookEvent("test", map[string]interface{}{
		"message":       "This is a test webhook delivery",
		"webhook_id":    webhook.ID,
		"webhook_label": webhook.Label,
	}, time.Now())
	if err != nil {
		slog.Error("failed to marshal test payload", "err", err)
		writeError(w, r, http.StatusInternalServerError, "failed to create test payload")
		return
	}

	taskPayload, err := tasks.MarshalWebhookPayload(tasks.WebhookSendPayload{
		WebhookID: webhook.ID,
		EventType: "test",
		Payload:   payloadBytes,
	})
	if err != nil {
		slog.Error("failed to marshal task payload", "err", err)
		writeError(w, r, http.StatusInternalServerError, "failed to create task")
		return
	}

	_, err = h.queue.EnqueueContext(r.Context(), asynq.NewTask(tasks.TypeWebhookSend, taskPayload), asynq.MaxRetry(5), asynq.Timeout(30*time.Second))
	if err != nil {
		slog.Error("failed to enqueue webhook test task", "err", err)
		writeError(w, r, http.StatusInternalServerError, "failed to enqueue test")
		return
	}

	slog.Info("enqueued webhook test", "webhook_id", webhook.ID)
	h.auditLog(r, "webhook.test", "webhook", webhook.ID, nil, nil)
	writeJSON(w, http.StatusOK, map[string]string{"status": "queued", "message": "Test webhook queued for delivery"})
}


