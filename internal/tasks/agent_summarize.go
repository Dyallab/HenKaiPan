package tasks

import (
	"context"
	"log/slog"

	"aspm/internal/agents"

	"github.com/hibiken/asynq"
)

func HandleAgentSummarize(summarizer *agents.SummaryAgent) asynq.HandlerFunc {
	return func(ctx context.Context, t *asynq.Task) error {
		p, err := UnmarshalAgentSummarizePayload(t.Payload())
		if err != nil {
			return err
		}

		log := slog.With("finding_id", p.FindingID)
		log.Info("agent:summarize started")

		summary, err := summarizer.Summarize(ctx, p.FindingID)
		if err != nil {
			log.Error("agent:summarize failed", "err", err)
			return err
		}

		log.Info("agent:summarize done", "summary_len", len(summary))
		return nil
	}
}
