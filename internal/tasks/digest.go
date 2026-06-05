package tasks

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"aspm/internal/ai"
	"aspm/internal/models"
	"aspm/internal/repository"

	"github.com/hibiken/asynq"
)

const TypeDigestSend = "digest:send"

func MarshalDigestPayload(p DigestPayload) ([]byte, error) {
	return json.Marshal(p)
}

type DigestPayload struct {
	Recipients []string `json:"recipients"`
}

func StartWeeklyDigestScheduler(ctx context.Context, store repository.Stores, queue *asynq.Client, notifications NotificationConfig) {
	go func() {
		for {
			now := time.Now()
			next := nextMonday9am(now)
			delay := next.Sub(now)

			slog.Info("weekly digest scheduler", "next_run", next.Format(time.RFC3339), "delay", delay.Round(time.Second))

			select {
			case <-time.After(delay):
				enqueueDigest(ctx, store, queue, notifications)
			case <-ctx.Done():
				slog.Info("digest scheduler stopped")
				return
			}
		}
	}()
	slog.Info("weekly digest scheduler started")
}

func nextMonday9am(t time.Time) time.Time {
	daysUntilMonday := (8 - int(t.Weekday())) % 7
	if daysUntilMonday == 0 {
		daysUntilMonday = 7
	}
	next := t.AddDate(0, 0, daysUntilMonday)
	return time.Date(next.Year(), next.Month(), next.Day(), 9, 0, 0, 0, next.Location())
}

func enqueueDigest(ctx context.Context, store repository.Stores, queue *asynq.Client, notifications NotificationConfig) {
	settings, err := store.Settings.GetNotificationSettings(ctx)
	if err != nil {
		slog.Error("digest: get notification settings", "err", err)
		return
	}
	if len(settings.EmailRecipients) == 0 {
		slog.Warn("digest: no email recipients configured, skipping")
		return
	}

	payload, err := MarshalDigestPayload(DigestPayload{
		Recipients: settings.EmailRecipients,
	})
	if err != nil {
		slog.Error("digest: marshal payload", "err", err)
		return
	}

	if _, err := queue.EnqueueContext(ctx,
		asynq.NewTask(TypeDigestSend, payload),
		asynq.MaxRetry(3),
		asynq.Timeout(2*time.Minute),
	); err != nil {
		slog.Error("digest: enqueue failed", "err", err)
	}
}

func HandleDigestSend(store repository.Stores, sender EmailSender, frontendURL string) asynq.HandlerFunc {
	return func(ctx context.Context, t *asynq.Task) error {
		var payload DigestPayload
		if err := json.Unmarshal(t.Payload(), &payload); err != nil {
			return fmt.Errorf("unmarshal digest payload: %w", err)
		}
		if len(payload.Recipients) == 0 {
			return nil
		}

		summary, err := store.Metrics.Summary(ctx)
		if err != nil {
			return fmt.Errorf("get metrics summary: %w", err)
		}

		trends, err := store.Metrics.Trends(ctx, 7)
		if err != nil {
			slog.Warn("digest: trends unavailable", "err", err)
			trends = nil
		}

		sla, err := store.Metrics.SLACompliance(ctx)
		if err != nil {
			slog.Warn("digest: SLA unavailable", "err", err)
			sla = nil
		}

		newFindings := 0
		if trends != nil {
			for _, t := range trends {
				newFindings += t.Critical + t.High + t.Medium + t.Low + t.Info
			}
		}

		slaPct := 0.0
		if sla != nil {
			slaPct = sla.Percent
		}

		dc := ai.DigestContext{
			TotalScans:       summary.TotalScans,
			TotalFindings:    summary.TotalFindings,
			CriticalCount:    summary.FindingsBySeverity["critical"],
			HighCount:        summary.FindingsBySeverity["high"],
			NewFindings:      newFindings,
			SLACompliancePct: slaPct,
		}

		narrative := ai.GenerateDigestNarrative(ctx, dc)
		body := buildDigestBody(summary, trends, sla, frontendURL)
		if narrative != "" {
			body = narrative + "\n\n---\n\n" + body
		}
		subject := fmt.Sprintf("HenKaiPan Weekly Digest — %s", time.Now().Format("Jan 2"))

		return sender.Send(ctx, payload.Recipients, subject, body)
	}
}

func buildDigestBody(summary *models.MetricsSummary, trends []models.TrendPoint, sla *models.SLACompliance, frontendURL string) string {
	var b strings.Builder

	b.WriteString("HenKaiPan Weekly Executive Digest\n")
	b.WriteString(strings.Repeat("=", 40) + "\n\n")

	b.WriteString(fmt.Sprintf("Period: %s – %s\n\n",
		time.Now().AddDate(0, 0, -7).Format("Jan 2"),
		time.Now().Format("Jan 2, 2006"),
	))

	b.WriteString("SCAN SUMMARY\n")
	b.WriteString(strings.Repeat("-", 40) + "\n")
	b.WriteString(fmt.Sprintf("  Total scans:     %d\n", summary.TotalScans))
	b.WriteString(fmt.Sprintf("  Active scans:    %d\n", summary.ActiveScans))
	b.WriteString(fmt.Sprintf("  Total findings:  %d\n", summary.TotalFindings))
	b.WriteString("\n")

	b.WriteString("FINDINGS BY SEVERITY\n")
	b.WriteString(strings.Repeat("-", 40) + "\n")
	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		count := summary.FindingsBySeverity[sev]
		marker := ""
		if sev == "critical" && count > 0 {
			marker = " ← URGENT"
		}
		if sev == "high" && count > 0 {
			marker = " ← ATTENTION"
		}
		b.WriteString(fmt.Sprintf("  %-10s %-4d%s\n", strings.ToUpper(sev)+":", count, marker))
	}
	b.WriteString("\n")

	if sla != nil {
		b.WriteString("SLA COMPLIANCE\n")
		b.WriteString(strings.Repeat("-", 40) + "\n")
		b.WriteString(fmt.Sprintf("  Compliance:      %.1f%%\n", sla.Percent))
		b.WriteString(fmt.Sprintf("  Overdue:         %d\n", sla.Overdue))
		b.WriteString(fmt.Sprintf("  On time:         %d\n", sla.OnTime))
		b.WriteString("\n")
	}

	if len(trends) > 0 {
		b.WriteString("7-DAY TREND (new findings per day)\n")
		b.WriteString(strings.Repeat("-", 40) + "\n")
		for _, t := range trends {
			total := t.Critical + t.High + t.Medium + t.Low + t.Info
			b.WriteString(fmt.Sprintf("  %s: %d (C:%d H:%d M:%d L:%d I:%d)\n",
				t.Date, total, t.Critical, t.High, t.Medium, t.Low, t.Info))
		}
		b.WriteString("\n")
	}

	if frontendURL != "" {
		b.WriteString("VIEW IN DASHBOARD\n")
		b.WriteString(strings.Repeat("-", 40) + "\n")
		b.WriteString(fmt.Sprintf("  %s/dashboard\n", strings.TrimRight(frontendURL, "/")))
		b.WriteString("\n")
	}

	b.WriteString("— HenKaiPan Security Platform\n")
	return b.String()
}
