package tasks

import (
	"context"
	"log/slog"

	"aspm/internal/events"
	"aspm/internal/findings"

	"github.com/hibiken/asynq"
)

func HandleFindingSummarize(summaryAgent *findings.SummaryAgent) asynq.HandlerFunc {
	return func(ctx context.Context, t *asynq.Task) error {
		p, err := UnmarshalFindingSummarizePayload(t.Payload())
		if err != nil {
			return err
		}

		log := slog.With("finding_id", p.FindingID)
		log.Info("agent:summarize started")

		summary, err := summaryAgent.Summarize(ctx, p.FindingID)
		if err != nil {
			log.Error("agent:summarize failed", "err", err)
			return err
		}

		log.Info("agent:summarize done", "summary_len", len(summary))

		// Publish SSE event for real-time frontend updates
		events.NewFindingSummaryCompleted(p.FindingID, summary).
			WithFindingID(p.FindingID).
			Publish()

		return nil
	}
}
