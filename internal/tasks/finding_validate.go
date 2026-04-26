package tasks

import (
	"context"
	"log/slog"

	"aspm/internal/findings"

	"github.com/hibiken/asynq"
)

func HandleFindingValidate(validator *findings.ValidationAgent) asynq.HandlerFunc {
	return func(ctx context.Context, t *asynq.Task) error {
		p, err := UnmarshalFindingValidatePayload(t.Payload())
		if err != nil {
			return err
		}

		log := slog.With("finding_id", p.FindingID)
		log.Info("agent:validate started")

		analysis, err := validator.Analyze(ctx, p.FindingID)
		if err != nil {
			log.Error("agent:validate failed", "err", err)
			return err
		}

		log.Info("agent:validate done",
			"confidence", analysis.Confidence,
			"fp_likelihood", analysis.FPLikelihood,
		)
		return nil
	}
}
