package tasks

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"aspm/internal/repository"
	wh "aspm/internal/webhook"

	"github.com/hibiken/asynq"
)

const (
	TypeWebhookSend = "webhook:send"
)

type WebhookSendPayload struct {
	WebhookID string `json:"webhook_id"`
	EventType string `json:"event_type"`
	Payload   []byte `json:"payload"`
}

type WebhookEventEnvelope struct {
	Event     string    `json:"event"`
	Data      any       `json:"data"`
	Timestamp time.Time `json:"timestamp"`
}

type slackBlockText struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type slackBlockField struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type slackSectionBlock struct {
	Type   string            `json:"type"`
	Text   *slackBlockText   `json:"text,omitempty"`
	Fields []slackBlockField `json:"fields,omitempty"`
}

type slackContextElement struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type slackContextBlock struct {
	Type     string                `json:"type"`
	Elements []slackContextElement `json:"elements"`
}

type slackWebhookMessage struct {
	Text   string `json:"text"`
	Blocks []any  `json:"blocks,omitempty"`
}

type discordEmbedField struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Inline bool   `json:"inline,omitempty"`
}

type discordEmbed struct {
	Title       string              `json:"title,omitempty"`
	Description string              `json:"description,omitempty"`
	Color       int                 `json:"color,omitempty"`
	Fields      []discordEmbedField `json:"fields,omitempty"`
	Timestamp   string              `json:"timestamp,omitempty"`
	Footer      *discordEmbedFooter `json:"footer,omitempty"`
}

type discordEmbedFooter struct {
	Text string `json:"text"`
}

type discordWebhookMessage struct {
	Content string         `json:"content,omitempty"`
	Embeds  []discordEmbed `json:"embeds,omitempty"`
}

func MarshalWebhookPayload(p WebhookSendPayload) ([]byte, error) {
	return json.Marshal(p)
}

func UnmarshalWebhookPayload(data []byte) (WebhookSendPayload, error) {
	var p WebhookSendPayload
	return p, json.Unmarshal(data, &p)
}

func MarshalWebhookEvent(eventType string, data any, now time.Time) ([]byte, error) {
	return json.Marshal(WebhookEventEnvelope{
		Event:     eventType,
		Data:      data,
		Timestamp: now.UTC(),
	})
}

func HandleWebhookSend(webhooks repository.WebhookRepository) asynq.HandlerFunc {
	return func(ctx context.Context, t *asynq.Task) error {
		p, err := UnmarshalWebhookPayload(t.Payload())
		if err != nil {
			return fmt.Errorf("unmarshal webhook payload: %w", err)
		}

		webhook, err := webhooks.GetByID(ctx, p.WebhookID)
		if err != nil {
			return fmt.Errorf("get webhook: %w", err)
		}

		if !webhook.Enabled {
			slog.Info("webhook disabled, skipping", "webhook_id", p.WebhookID)
			return nil
		}

		log := slog.With("webhook_id", p.WebhookID, "event_type", p.EventType, "url_host", webhookURLHost(webhook.URL))
		if err := validateOutboundWebhookURL(webhook.URL); err != nil {
			log.Error("webhook url rejected", "err", err)
			updateDeliveryStats(ctx, webhooks, p.WebhookID, false, 0, "", err.Error())
			logDelivery(ctx, webhooks, WebhookSendPayload{WebhookID: p.WebhookID, EventType: p.EventType, Payload: p.Payload}, 0, "", err.Error())
			return fmt.Errorf("validate webhook url: %w", err)
		}

		body, err := formatWebhookBody(webhook.DeliveryType, p.Payload)
		if err != nil {
			log.Error("format webhook payload failed", "err", err)
			updateDeliveryStats(ctx, webhooks, p.WebhookID, false, 0, "", err.Error())
			logDelivery(ctx, webhooks, WebhookSendPayload{WebhookID: p.WebhookID, EventType: p.EventType, Payload: body}, 0, "", err.Error())
			return fmt.Errorf("format webhook payload: %w", err)
		}

		req, err := http.NewRequestWithContext(ctx, "POST", webhook.URL, bytes.NewReader(body))
		if err != nil {
			log.Error("create request failed", "err", err)
			return fmt.Errorf("create request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "ASPM-Webhook/1.0")
		req.Header.Set("X-ASPM-Event", p.EventType)

		// Add HMAC signature headers if WEBHOOK_SECRET is configured
		if secret := os.Getenv("WEBHOOK_SECRET"); secret != "" {
			timestamp := time.Now()
			signature := wh.SignPayload(body, []byte(secret), timestamp)
			req.Header.Set(wh.SignatureHeader, signature)
			req.Header.Set(wh.TimestampHeader, timestamp.Format(time.RFC3339))
		}

		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			log.Error("request failed", "err", err)
			updateDeliveryStats(ctx, webhooks, p.WebhookID, false, 0, "", err.Error())
			logDelivery(ctx, webhooks, WebhookSendPayload{WebhookID: p.WebhookID, EventType: p.EventType, Payload: body}, 0, "", err.Error())
			return fmt.Errorf("send webhook: %w", err)
		}
		defer resp.Body.Close()

		respBody, _ := io.ReadAll(resp.Body)
		success := resp.StatusCode >= 200 && resp.StatusCode < 300
		var errorMsg string
		if !success {
			errorMsg = fmt.Sprintf("unexpected status code: %d", resp.StatusCode)
		}

		updateDeliveryStats(ctx, webhooks, p.WebhookID, success, resp.StatusCode, string(respBody), errorMsg)
		logDelivery(ctx, webhooks, WebhookSendPayload{WebhookID: p.WebhookID, EventType: p.EventType, Payload: body}, resp.StatusCode, string(respBody), errorMsg)

		if !success {
			return fmt.Errorf("%s", errorMsg)
		}

		log.Info("webhook delivered", "status", resp.StatusCode)
		return nil
	}
}

func validateOutboundWebhookURL(raw string) error {
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

func webhookURLHost(raw string) string {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "invalid"
	}
	return parsed.Hostname()
}

func formatWebhookBody(deliveryType string, payload []byte) ([]byte, error) {
	deliveryType = strings.ToLower(strings.TrimSpace(deliveryType))
	if deliveryType == "" || deliveryType == "generic" {
		return payload, nil
	}

	var envelope WebhookEventEnvelope
	if err := json.Unmarshal(payload, &envelope); err != nil {
		return nil, fmt.Errorf("decode webhook envelope: %w", err)
	}

	summary := formatWebhookSummary(envelope)
	card := buildWebhookCard(envelope)

	switch deliveryType {
	case "slack":
		message := slackWebhookMessage{
			Text: summary,
			Blocks: []any{
				slackSectionBlock{
					Type: "section",
					Text: &slackBlockText{Type: "mrkdwn", Text: fmt.Sprintf("*%s*\n%s", card.Title, card.Description)},
				},
			},
		}
		if len(card.Fields) > 0 {
			message.Blocks = append(message.Blocks, slackSectionBlock{Type: "section", Fields: card.Fields})
		}
		if card.Context != "" {
			message.Blocks = append(message.Blocks, slackContextBlock{Type: "context", Elements: []slackContextElement{{Type: "mrkdwn", Text: card.Context}}})
		}
		return json.Marshal(message)
	case "discord":
		embedFields := make([]discordEmbedField, 0, len(card.Fields))
		for _, field := range card.Fields {
			parts := strings.SplitN(field.Text, "\n", 2)
			if len(parts) != 2 {
				continue
			}
			embedFields = append(embedFields, discordEmbedField{Name: strings.Trim(parts[0], "*"), Value: parts[1], Inline: true})
		}
		message := discordWebhookMessage{
			Content: card.Prefix,
			Embeds: []discordEmbed{{
				Title:       card.Title,
				Description: card.Description,
				Color:       webhookColor(envelope.Event),
				Fields:      embedFields,
				Timestamp:   envelope.Timestamp.UTC().Format(time.RFC3339),
				Footer:      &discordEmbedFooter{Text: card.Context},
			}},
		}
		return json.Marshal(message)
	default:
		return nil, fmt.Errorf("unsupported delivery type: %s", deliveryType)
	}
}

func formatWebhookSummary(envelope WebhookEventEnvelope) string {
	switch envelope.Event {
	case "finding.critical":
		return "🚨 Critical finding detected"
	case "finding.high":
		return "⚠️ High severity finding detected"
	case "finding.sla_breach":
		return "⏰ Finding SLA breached"
	case "scan.completed":
		return "✅ Scan completed"
	case "scan.failed":
		return "❌ Scan failed"
	case "test":
		return "🧪 Webhook test from HenKaiPan"
	default:
		return fmt.Sprintf("Webhook event: %s", envelope.Event)
	}
}

type webhookCard struct {
	Prefix      string
	Title       string
	Description string
	Fields      []slackBlockField
	Context     string
}

func buildWebhookCard(envelope WebhookEventEnvelope) webhookCard {
	dataMap, ok := envelope.Data.(map[string]any)
	if !ok {
		return webhookCard{
			Prefix:      formatWebhookSummary(envelope),
			Title:       formatWebhookSummary(envelope),
			Description: fmt.Sprintf("Event `%s` from ASPM webhook delivery.", envelope.Event),
			Context:     fmt.Sprintf("Event %s • %s", envelope.Event, envelope.Timestamp.UTC().Format(time.RFC3339)),
		}
	}

	card := webhookCard{Prefix: formatWebhookSummary(envelope), Title: formatWebhookSummary(envelope)}
	switch envelope.Event {
	case "finding.critical", "finding.high", "finding.sla_breach":
		severity := strings.ToUpper(stringFromAny(dataMap["severity"]))
		title := stringFromAny(dataMap["title"])
		repo := stringFromAny(dataMap["repository"])
		ruleID := stringFromAny(dataMap["rule_id"])
		location := buildLocationLabel(dataMap)
		aiSummary := strings.TrimSpace(stringFromAny(dataMap["ai_summary"]))
		if envelope.Event == "finding.sla_breach" {
			card.Title = fmt.Sprintf("SLA breached · %s", title)
			card.Description = "A finding passed its SLA deadline and still requires action."
		} else {
			card.Title = fmt.Sprintf("%s · %s", severity, title)
			if aiSummary != "" {
				card.Description = aiSummary
			} else {
				card.Description = strings.TrimSpace(stringFromAny(dataMap["description"]))
			}
		}
		if card.Description == "" {
			card.Description = "A security finding matched the configured severity threshold and triggered this notification."
		}
		card.Fields = make([]slackBlockField, 0, 7)
		appendCardField(&card.Fields, "Severity", severity)
		appendCardField(&card.Fields, "Scanner", stringFromAny(dataMap["scanner"]))
		appendCardField(&card.Fields, "Repository", repo)
		appendCardField(&card.Fields, "Rule ID", ruleID)
		appendCardField(&card.Fields, "Location", location)
		appendCardField(&card.Fields, "Finding ID", stringFromAny(dataMap["finding_id"]))
		if envelope.Event == "finding.sla_breach" {
			appendCardField(&card.Fields, "SLA Deadline", formatHumanTime(dataMap["sla_deadline"], envelope.Timestamp))
		}
		card.Context = strings.TrimSpace(strings.Join([]string{repo, envelope.Event, formatHumanTime(dataMap["created_at"], envelope.Timestamp)}, " • "))
	case "scan.completed":
		scanner := stringFromAny(dataMap["scanner"])
		target := stringFromAny(dataMap["target"])
		count := stringFromAny(dataMap["finding_count"])
		card.Title = fmt.Sprintf("%s finished cleanly", scanner)
		card.Description = fmt.Sprintf("Scan completed for `%s` with %s findings recorded.", target, count)
		card.Fields = make([]slackBlockField, 0, 5)
		appendCardField(&card.Fields, "Scanner", scanner)
		appendCardField(&card.Fields, "Target", target)
		appendCardField(&card.Fields, "Status", strings.ToUpper(stringFromAny(dataMap["status"])))
		appendCardField(&card.Fields, "Findings", count)
		appendCardField(&card.Fields, "Scan ID", stringFromAny(dataMap["scan_id"]))
		card.Context = strings.TrimSpace(strings.Join([]string{envelope.Event, formatHumanTime(dataMap["completed_at"], envelope.Timestamp)}, " • "))
	case "scan.failed":
		scanner := stringFromAny(dataMap["scanner"])
		target := stringFromAny(dataMap["target"])
		errMsg := strings.TrimSpace(stringFromAny(dataMap["error"]))
		card.Title = fmt.Sprintf("%s scan failed", scanner)
		if errMsg == "" {
			errMsg = "The scanner returned a failure without a detailed error message."
		}
		card.Description = errMsg
		card.Fields = make([]slackBlockField, 0, 5)
		appendCardField(&card.Fields, "Scanner", scanner)
		appendCardField(&card.Fields, "Target", target)
		appendCardField(&card.Fields, "Status", strings.ToUpper(stringFromAny(dataMap["status"])))
		appendCardField(&card.Fields, "Findings", stringFromAny(dataMap["finding_count"]))
		appendCardField(&card.Fields, "Scan ID", stringFromAny(dataMap["scan_id"]))
		card.Context = strings.TrimSpace(strings.Join([]string{envelope.Event, formatHumanTime(dataMap["completed_at"], envelope.Timestamp)}, " • "))
	case "test":
		card.Title = "Webhook test from HenKaiPan"
		card.Description = "This confirms the webhook endpoint accepted an ASPM delivery."
		card.Fields = make([]slackBlockField, 0, 3)
		appendCardField(&card.Fields, "Webhook", stringFromAny(dataMap["webhook_label"]))
		appendCardField(&card.Fields, "Webhook ID", stringFromAny(dataMap["webhook_id"]))
		appendCardField(&card.Fields, "Event", envelope.Event)
		card.Context = formatHumanTime(dataMap["timestamp"], envelope.Timestamp)
	default:
		card.Description = fmt.Sprintf("Event `%s` from ASPM webhook delivery.", envelope.Event)
		card.Fields = make([]slackBlockField, 0, 1)
		appendCardField(&card.Fields, "Event", envelope.Event)
		card.Context = envelope.Timestamp.UTC().Format(time.RFC3339)
	}
	return card
}

func appendCardField(fields *[]slackBlockField, label, value string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return
	}
	*fields = append(*fields, slackBlockField{Type: "mrkdwn", Text: fmt.Sprintf("*%s*\n%s", label, value)})
}

func stringFromAny(value any) string {
	switch v := value.(type) {
	case string:
		return v
	case fmt.Stringer:
		return v.String()
	case float64:
		return fmt.Sprintf("%.0f", v)
	case int:
		return fmt.Sprintf("%d", v)
	default:
		return ""
	}
}

func buildLocationLabel(dataMap map[string]any) string {
	path := stringFromAny(dataMap["file_path"])
	line := stringFromAny(dataMap["line"])
	if path == "" {
		return ""
	}
	if line == "" {
		return path
	}
	return fmt.Sprintf("%s:%s", path, line)
}

func formatHumanTime(value any, fallback time.Time) string {
	raw := strings.TrimSpace(stringFromAny(value))
	if raw == "" {
		return fallback.UTC().Format(time.RFC3339)
	}
	if ts, err := time.Parse(time.RFC3339, raw); err == nil {
		return ts.UTC().Format(time.RFC3339)
	}
	return raw
}

func webhookColor(event string) int {
	switch event {
	case "finding.critical", "finding.sla_breach", "scan.failed":
		return 0xE11D48
	case "finding.high":
		return 0xF97316
	case "scan.completed":
		return 0x10B981
	default:
		return 0x38BDF8
	}
}

func updateDeliveryStats(ctx context.Context, webhooks repository.WebhookRepository, webhookID string, success bool, statusCode int, responseBody string, errorMsg string) {
	if err := webhooks.UpdateDeliveryStats(ctx, webhookID, success, statusCode, responseBody, errorMsg); err != nil {
		slog.Error("failed to update delivery stats", "webhook_id", webhookID, "err", err)
	}
}

func logDelivery(ctx context.Context, webhooks repository.WebhookRepository, p WebhookSendPayload, statusCode int, responseBody string, errorMsg string) {
	var statusPtr *int
	if statusCode != 0 {
		statusPtr = &statusCode
	}
	var responsePtr *string
	if responseBody != "" {
		responsePtr = &responseBody
	}
	var errorPtr *string
	if errorMsg != "" {
		errorPtr = &errorMsg
	}

	err := webhooks.LogDelivery(ctx, repository.WebhookDeliveryInsert{
		WebhookID:    p.WebhookID,
		EventType:    p.EventType,
		Payload:      p.Payload,
		StatusCode:   statusPtr,
		ResponseBody: responsePtr,
		ErrorMessage: errorPtr,
	})
	if err != nil {
		slog.Error("failed to log delivery", "webhook_id", p.WebhookID, "err", err)
	}
}
