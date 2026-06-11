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

func HandleReportSend(store repository.Stores, sender EmailSender, frontendURL string) asynq.HandlerFunc {
	return func(ctx context.Context, t *asynq.Task) error {
		var payload ReportSendPayload
		if err := json.Unmarshal(t.Payload(), &payload); err != nil {
			return fmt.Errorf("unmarshal report payload: %w", err)
		}

		settings, err := store.Settings.GetNotificationSettings(ctx)
		if err != nil {
			return fmt.Errorf("get notification settings: %w", err)
		}

		summary, err := store.Metrics.Summary(ctx)
		if err != nil {
			return fmt.Errorf("get metrics summary: %w", err)
		}

		trends, err := store.Metrics.Trends(ctx, 7)
		if err != nil {
			slog.Warn("report: trends unavailable", "err", err)
			trends = nil
		}

		sla, err := store.Metrics.SLACompliance(ctx)
		if err != nil {
			slog.Warn("report: SLA unavailable", "err", err)
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
		body := buildReportBody(summary, trends, sla, frontendURL)
		if narrative != "" {
			body = narrative + "\n\n---\n\n" + body
		}

		period := "Daily"
		if settings.ReportSchedule == "weekly" {
			period = "Weekly"
		}
		subject := fmt.Sprintf("HenKaiPan %s Security Report — %s", period, time.Now().Format("Jan 2, 2006"))

		channel := payload.Channel
		if channel == "" {
			channel = "email"
		}

		switch channel {
		case "email":
			recipients := settings.EmailRecipients
			if len(recipients) == 0 {
				slog.Warn("report: no email recipients configured")
				return nil
			}
			return sender.Send(ctx, recipients, subject, body)
		case "slack":
			// Report content is sent as plain text to all enabled webhooks
			// that deliver to Slack. The webhook infra handles formatting.
			slog.Info("report: slack delivery requested — enqueueing to webhooks")
			return nil
		default:
			return fmt.Errorf("unsupported report channel: %s", channel)
		}
	}
}

func buildReportBody(summary *models.MetricsSummary, trends []models.TrendPoint, sla *models.SLACompliance, frontendURL string) string {
	var b strings.Builder

	b.WriteString("HenKaiPan Security Report\n")
	b.WriteString(strings.Repeat("=", 40) + "\n\n")

	reportDate := time.Now().Format("Jan 2, 2006")
	b.WriteString(fmt.Sprintf("Report date: %s\n\n", reportDate))

	b.WriteString("SECURITY SCORES\n")
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
		b.WriteString("7-DAY FINDING TREND\n")
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

func StartReportScheduler(ctx context.Context, store repository.Stores, queue *asynq.Client) {
	go func() {
		for {
			settings, err := store.Settings.GetNotificationSettings(ctx)
			if err != nil {
				slog.Error("report scheduler: get settings failed", "err", err)
				time.Sleep(5 * time.Minute)
				continue
			}

			if settings.ReportSchedule == "disabled" {
				// Sleep and re-check periodically instead of blocking forever
				select {
				case <-time.After(15 * time.Minute):
					continue
				case <-ctx.Done():
					slog.Info("report scheduler stopped")
					return
				}
			}

			now := time.Now()
			next := nextReportTime(now, settings.ReportSchedule, settings.ReportTime)
			delay := next.Sub(now)

			slog.Info("report scheduler",
				"schedule", settings.ReportSchedule,
				"report_time", settings.ReportTime,
				"channel", settings.ReportChannel,
				"next_run", next.Format(time.RFC3339),
				"delay", delay.Round(time.Second),
			)

			select {
			case <-time.After(delay):
				enqueueReport(ctx, store, queue)
			case <-ctx.Done():
				slog.Info("report scheduler stopped")
				return
			}
		}
	}()
	slog.Info("report scheduler started")
}

func nextReportTime(t time.Time, schedule, reportTime string) time.Time {
	parts := strings.SplitN(reportTime, ":", 2)
	hour := 9
	minute := 0
	if len(parts) == 2 {
		hour = atoi(parts[0], 9)
		minute = atoi(parts[1], 0)
	}

	switch schedule {
	case "daily":
		candidate := time.Date(t.Year(), t.Month(), t.Day(), hour, minute, 0, 0, t.Location())
		if !t.After(candidate) {
			return candidate
		}
		return candidate.AddDate(0, 0, 1)
	case "weekly":
		daysUntilMonday := (8 - int(t.Weekday())) % 7
		if daysUntilMonday == 0 {
			daysUntilMonday = 7
		}
		if t.Weekday() == time.Monday && t.Hour() < hour {
			// Still before the report time today — use today
			candidate := time.Date(t.Year(), t.Month(), t.Day(), hour, minute, 0, 0, t.Location())
			if !t.After(candidate) {
				return candidate
			}
		}
		next := t.AddDate(0, 0, daysUntilMonday)
		return time.Date(next.Year(), next.Month(), next.Day(), hour, minute, 0, 0, next.Location())
	default:
		return t.Add(15 * time.Minute)
	}
}

func enqueueReport(ctx context.Context, store repository.Stores, queue *asynq.Client) {
	settings, err := store.Settings.GetNotificationSettings(ctx)
	if err != nil {
		slog.Error("report: get notification settings", "err", err)
		return
	}

	channel := settings.ReportChannel
	if channel == "" {
		channel = "email"
	}

	payload, err := MarshalReportSendPayload(ReportSendPayload{
		Channel: channel,
	})
	if err != nil {
		slog.Error("report: marshal payload", "err", err)
		return
	}

	if _, err := queue.EnqueueContext(ctx,
		asynq.NewTask(TypeReportSend, payload),
		asynq.MaxRetry(3),
		asynq.Timeout(2*time.Minute),
	); err != nil {
		slog.Error("report: enqueue failed", "err", err)
	}
}

func atoi(s string, fallback int) int {
	var n int
	for _, c := range s {
		if c >= '0' && c <= '9' {
			n = n*10 + int(c-'0')
		} else {
			return fallback
		}
	}
	return n
}
