package models

import "time"

type Webhook struct {
	ID            string     `json:"id"`
	Label         string     `json:"label"`
	URL           string     `json:"url"`
	DeliveryType  string     `json:"delivery_type"`
	Events        []string   `json:"events"`
	Enabled       bool       `json:"enabled"`
	LastDelivery  *time.Time `json:"last_delivery,omitempty"`
	DeliveryCount int        `json:"delivery_count"`
	ErrorCount    int        `json:"error_count"`
	LastError     *string    `json:"last_error,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
}

type WebhookDeliveryLog struct {
	ID           string     `json:"id"`
	WebhookID    string     `json:"webhook_id"`
	EventType    string     `json:"event_type"`
	Payload      []byte     `json:"payload"`
	StatusCode   *int       `json:"status_code,omitempty"`
	ResponseBody *string    `json:"response_body,omitempty"`
	ErrorMessage *string    `json:"error_message,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
}
