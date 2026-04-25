package webhook

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"aspm/internal/repository"
	"aspm/internal/tasks"

	"github.com/hibiken/asynq"
)

type Dispatcher struct {
	webhooks repository.WebhookRepository
	queue    *asynq.Client
}

func NewDispatcher(webhooks repository.WebhookRepository, queue *asynq.Client) *Dispatcher {
	return &Dispatcher{
		webhooks: webhooks,
		queue:    queue,
	}
}

func (d *Dispatcher) Dispatch(ctx context.Context, eventType string, payload interface{}) error {
	webhooks, err := d.webhooks.ListEnabled(ctx)
	if err != nil {
		slog.Error("failed to list enabled webhooks", "err", err)
		return err
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		slog.Error("failed to marshal webhook payload", "err", err)
		return err
	}

	for _, webhook := range webhooks {
		if !containsEvent(webhook.Events, eventType) {
			continue
		}

		taskPayload, err := tasks.MarshalWebhookPayload(tasks.WebhookSendPayload{
			WebhookID: webhook.ID,
			EventType: eventType,
			Payload:   payloadBytes,
		})
		if err != nil {
			slog.Error("failed to marshal task payload", "webhook_id", webhook.ID, "err", err)
			continue
		}

		_, err = d.queue.EnqueueContext(ctx, asynq.NewTask(tasks.TypeWebhookSend, taskPayload))
		if err != nil {
			slog.Error("failed to enqueue webhook task", "webhook_id", webhook.ID, "err", err)
			continue
		}

		slog.Info("enqueued webhook delivery", "webhook_id", webhook.ID, "event_type", eventType)
	}

	return nil
}

func containsEvent(events []string, event string) bool {
	for _, e := range events {
		if e == event {
			return true
		}
	}
	return false
}

type EventPayload struct {
	Event     string      `json:"event"`
	Data      interface{} `json:"data"`
	Timestamp time.Time   `json:"timestamp"`
}

type FindingCreatedPayload struct {
	FindingID   string    `json:"finding_id"`
	Repository  string    `json:"repository"`
	Severity    string    `json:"severity"`
	Title       string    `json:"title"`
	RuleID      string    `json:"rule_id"`
	FilePath    string    `json:"file_path"`
	Line        int       `json:"line"`
	Scanner     string    `json:"scanner"`
	Description string    `json:"description,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

type ScanCompletedPayload struct {
	ScanID      string    `json:"scan_id"`
	Target      string    `json:"target"`
	Scanner     string    `json:"scanner"`
	Status      string    `json:"status"`
	Findings    int       `json:"findings"`
	Error       string    `json:"error,omitempty"`
	CompletedAt time.Time `json:"completed_at"`
}
