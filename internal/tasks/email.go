package tasks

import (
	"context"
	"encoding/json"
	"fmt"
	"net/smtp"
	"strings"
	"time"

	"github.com/hibiken/asynq"
)

const TypeEmailSend = "email:send"

type EmailConfig struct {
	Host     string
	Port     string
	Username string
	Password string
	From     string
	Enabled  bool
}

type EmailSendPayload struct {
	Subject string   `json:"subject"`
	Body    string   `json:"body"`
	To      []string `json:"to,omitempty"`
}

type EmailSender interface {
	Enabled() bool
	Send(ctx context.Context, to []string, subject, body string) error
}

type SMTPEmailSender struct {
	cfg EmailConfig
}

func NewSMTPEmailSender(cfg EmailConfig) SMTPEmailSender {
	return SMTPEmailSender{cfg: cfg}
}

func (s SMTPEmailSender) Enabled() bool {
	return s.cfg.Enabled
}

func (s SMTPEmailSender) Send(ctx context.Context, to []string, subject, body string) error {
	if !s.cfg.Enabled {
		return nil
	}

	addr := s.cfg.Host + ":" + s.cfg.Port
	var auth smtp.Auth
	if strings.TrimSpace(s.cfg.Username) != "" || strings.TrimSpace(s.cfg.Password) != "" {
		auth = smtp.PlainAuth("", s.cfg.Username, s.cfg.Password, s.cfg.Host)
	}
	message := buildEmailMessage(s.cfg.From, to, subject, body)

	done := make(chan error, 1)
	go func() {
		done <- smtp.SendMail(addr, auth, s.cfg.From, to, []byte(message))
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-done:
		if err != nil {
			return fmt.Errorf("send email: %w", err)
		}
		return nil
	case <-time.After(20 * time.Second):
		return fmt.Errorf("send email timeout")
	}
}

func MarshalEmailSendPayload(p EmailSendPayload) ([]byte, error) {
	return json.Marshal(p)
}

func HandleEmailSend(sender EmailSender) asynq.HandlerFunc {
	return func(ctx context.Context, t *asynq.Task) error {
		if !sender.Enabled() {
			return nil
		}
		var payload EmailSendPayload
		if err := json.Unmarshal(t.Payload(), &payload); err != nil {
			return fmt.Errorf("unmarshal email payload: %w", err)
		}
		recipients := payload.To
		if strings.TrimSpace(payload.Subject) == "" || strings.TrimSpace(payload.Body) == "" || len(recipients) == 0 {
			return fmt.Errorf("email payload incomplete")
		}
		return sender.Send(ctx, recipients, payload.Subject, payload.Body)
	}
}

func buildEmailMessage(from string, to []string, subject, body string) string {
	headers := []string{
		"From: " + from,
		"To: " + strings.Join(to, ", "),
		"Subject: " + sanitizeEmailHeader(subject),
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=UTF-8",
	}
	return strings.Join(headers, "\r\n") + "\r\n\r\n" + strings.TrimSpace(body) + "\r\n"
}

func sanitizeEmailHeader(value string) string {
	value = strings.ReplaceAll(value, "\r", " ")
	value = strings.ReplaceAll(value, "\n", " ")
	return strings.TrimSpace(value)
}
