package repository

import (
	"context"
	"encoding/json"
	"fmt"

	"aspm/internal/models"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type webhookRepo struct {
	db *pgxpool.Pool
}

func (r *webhookRepo) List(ctx context.Context) ([]models.Webhook, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, label, url, delivery_type, events, enabled, last_delivery, delivery_count, error_count, last_error, created_at
		FROM webhooks ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("webhooks list: %w", err)
	}
	defer rows.Close()

	var out []models.Webhook
	for rows.Next() {
		var w models.Webhook
		var eventsRaw []byte
		if err := rows.Scan(&w.ID, &w.Label, &w.URL, &w.DeliveryType, &eventsRaw, &w.Enabled, &w.LastDelivery, &w.DeliveryCount, &w.ErrorCount, &w.LastError, &w.CreatedAt); err != nil {
			continue
		}
		json.Unmarshal(eventsRaw, &w.Events)
		if w.Events == nil {
			w.Events = []string{}
		}
		out = append(out, w)
	}
	return EnsureSlice(out), nil
}

func (r *webhookRepo) GetByID(ctx context.Context, id string) (*models.Webhook, error) {
	var w models.Webhook
	var eventsRaw []byte
	err := r.db.QueryRow(ctx, `
		SELECT id, label, url, delivery_type, events, enabled, last_delivery, delivery_count, error_count, last_error, created_at
		FROM webhooks WHERE id = $1`, id).Scan(&w.ID, &w.Label, &w.URL, &w.DeliveryType, &eventsRaw, &w.Enabled, &w.LastDelivery, &w.DeliveryCount, &w.ErrorCount, &w.LastError, &w.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("get webhook: %w", err)
	}
	json.Unmarshal(eventsRaw, &w.Events)
	if w.Events == nil {
		w.Events = []string{}
	}
	return &w, nil
}

func (r *webhookRepo) Create(ctx context.Context, wc WebhookCreate) (*models.Webhook, error) {
	eventsJSON, _ := json.Marshal(wc.Events)

	var w models.Webhook
	var eventsRaw []byte
	err := r.db.QueryRow(ctx, `
		INSERT INTO webhooks (label, url, delivery_type, events)
		VALUES ($1, $2, $3, $4)
		RETURNING id, label, url, delivery_type, events, enabled, last_delivery, delivery_count, error_count, last_error, created_at`,
		wc.Label, wc.URL, wc.DeliveryType, eventsJSON,
	).Scan(&w.ID, &w.Label, &w.URL, &w.DeliveryType, &eventsRaw, &w.Enabled, &w.LastDelivery, &w.DeliveryCount, &w.ErrorCount, &w.LastError, &w.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("create webhook: %w", err)
	}
	json.Unmarshal(eventsRaw, &w.Events)
	return &w, nil
}

func (r *webhookRepo) Update(ctx context.Context, id string, upd WebhookUpdate) (*models.Webhook, error) {
	var w models.Webhook
	var eventsRaw []byte

	args := pgx.NamedArgs{"id": id}
	var setClauses []string

	if upd.Label != nil {
		setClauses = append(setClauses, "label = @label")
		args["label"] = *upd.Label
	}
	if upd.URL != nil {
		setClauses = append(setClauses, "url = @url")
		args["url"] = *upd.URL
	}
	if upd.DeliveryType != nil {
		setClauses = append(setClauses, "delivery_type = @delivery_type")
		args["delivery_type"] = *upd.DeliveryType
	}
	if upd.Events != nil {
		eventsJSON, _ := json.Marshal(upd.Events)
		setClauses = append(setClauses, "events = @events")
		args["events"] = eventsJSON
	}
	if upd.Enabled != nil {
		setClauses = append(setClauses, "enabled = @enabled")
		args["enabled"] = *upd.Enabled
	}

	if len(setClauses) == 0 {
		return r.GetByID(ctx, id)
	}

	query := `UPDATE webhooks SET ` + setClauses[0]
	for i := 1; i < len(setClauses); i++ {
		query += ", " + setClauses[i]
	}
	query += ` WHERE id = @id RETURNING id, label, url, delivery_type, events, enabled, last_delivery, delivery_count, error_count, last_error, created_at`

	err := r.db.QueryRow(ctx, query, args).Scan(&w.ID, &w.Label, &w.URL, &w.DeliveryType, &eventsRaw, &w.Enabled, &w.LastDelivery, &w.DeliveryCount, &w.ErrorCount, &w.LastError, &w.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("update webhook: %w", err)
	}
	json.Unmarshal(eventsRaw, &w.Events)
	return &w, nil
}

func (r *webhookRepo) Delete(ctx context.Context, id string) error {
	return DeleteByID(ctx, r.db, "webhooks", id)
}

func (r *webhookRepo) ListEnabled(ctx context.Context) ([]models.Webhook, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, label, url, delivery_type, events, enabled, last_delivery, delivery_count, error_count, last_error, created_at
		FROM webhooks WHERE enabled = TRUE`)
	if err != nil {
		return nil, fmt.Errorf("list enabled webhooks: %w", err)
	}
	defer rows.Close()

	var out []models.Webhook
	for rows.Next() {
		var w models.Webhook
		var eventsRaw []byte
		if err := rows.Scan(&w.ID, &w.Label, &w.URL, &w.DeliveryType, &eventsRaw, &w.Enabled, &w.LastDelivery, &w.DeliveryCount, &w.ErrorCount, &w.LastError, &w.CreatedAt); err != nil {
			continue
		}
		json.Unmarshal(eventsRaw, &w.Events)
		if w.Events == nil {
			w.Events = []string{}
		}
		out = append(out, w)
	}
	return out, nil
}

func (r *webhookRepo) UpdateDeliveryStats(ctx context.Context, id string, success bool, statusCode int, responseBody string, errorMsg string) error {
	query := `
		UPDATE webhooks 
		SET last_delivery = NOW(),
		    delivery_count = delivery_count + 1,
		    error_count = error_count + CASE WHEN @success THEN 0 ELSE 1 END,
		    last_error = CASE WHEN @success THEN NULL ELSE @error_msg END
		WHERE id = @id`
	
	_, err := r.db.Exec(ctx, query, pgx.NamedArgs{
		"success":    success,
		"error_msg":  errorMsg,
		"id":         id,
	})
	return err
}

func (r *webhookRepo) LogDelivery(ctx context.Context, l WebhookDeliveryInsert) error {
	_, err := r.db.Exec(ctx, `
		INSERT INTO webhook_delivery_logs (webhook_id, event_type, payload, status_code, response_body, error_message)
		VALUES (@webhook_id, @event_type, @payload, @status_code, @response_body, @error_message)`,
		pgx.NamedArgs{
			"webhook_id":    l.WebhookID,
			"event_type":    l.EventType,
			"payload":       l.Payload,
			"status_code":   l.StatusCode,
			"response_body": l.ResponseBody,
			"error_message": l.ErrorMessage,
		})
	return err
}

func (r *webhookRepo) GetDeliveryLogs(ctx context.Context, webhookID string, limit int) ([]models.WebhookDeliveryLog, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, webhook_id, event_type, payload, status_code, response_body, error_message, created_at
		FROM webhook_delivery_logs 
		WHERE webhook_id = $1 
		ORDER BY created_at DESC 
		LIMIT $2`, webhookID, limit)
	if err != nil {
		return nil, fmt.Errorf("get delivery logs: %w", err)
	}
	defer rows.Close()

	var out []models.WebhookDeliveryLog
	for rows.Next() {
		var l models.WebhookDeliveryLog
		if err := rows.Scan(&l.ID, &l.WebhookID, &l.EventType, &l.Payload, &l.StatusCode, &l.ResponseBody, &l.ErrorMessage, &l.CreatedAt); err != nil {
			continue
		}
		out = append(out, l)
	}
	return out, nil
}
