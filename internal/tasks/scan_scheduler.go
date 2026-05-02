package tasks

import (
	"context"
	"log/slog"
	"time"

	"aspm/internal/repository"

	"github.com/hibiken/asynq"
	"github.com/robfig/cron/v3"
)

func StartScanScheduler(ctx context.Context, store repository.Stores, queue *asynq.Client, interval time.Duration) {
	cronParser := cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		runDueSchedules(ctx, store, queue, cronParser)

		for {
			select {
			case <-ticker.C:
				runDueSchedules(ctx, store, queue, cronParser)
			case <-ctx.Done():
				slog.Info("scan scheduler stopped")
				return
			}
		}
	}()

	slog.Info("scan scheduler started", "interval", interval)
}

func runDueSchedules(ctx context.Context, store repository.Stores, queue *asynq.Client, parser cron.Parser) {
	schedules, err := store.Schedules.ListDue(ctx)
	if err != nil {
		slog.Error("list due schedules", "err", err)
		return
	}

	for _, s := range schedules {
		project, err := store.Apps.GetProjectByID(ctx, s.ProjectID)
		if err != nil {
			slog.Error("get schedule project", "schedule_id", s.ID, "project_id", s.ProjectID, "err", err)
			continue
		}
		if project.RepoURL == nil || *project.RepoURL == "" {
			slog.Warn("schedule project has no repo URL, skipping", "schedule_id", s.ID, "project_id", s.ProjectID)
			continue
		}

		target := *project.RepoURL

		scanID, err := store.Scans.Insert(ctx, target, s.Scanner, "scheduled", &s.ProjectID)
		if err != nil {
			slog.Error("create scheduled scan", "schedule_id", s.ID, "err", err)
			continue
		}

		payload, err := MarshalScanPayload(ScanPayload{
			ScanID:    scanID,
			ProjectID: s.ProjectID,
			Target:    target,
			Scanner:   s.Scanner,
		})
		if err != nil {
			slog.Error("marshal scan payload", "schedule_id", s.ID, "err", err)
			continue
		}

		if _, err := queue.EnqueueContext(ctx,
			asynq.NewTask(TypeScanRun, payload),
			asynq.MaxRetry(3),
			asynq.Timeout(30*time.Minute),
		); err != nil {
			slog.Error("enqueue scheduled scan", "schedule_id", s.ID, "err", err)
			continue
		}

		var nextRun *time.Time
		sched, err := parser.Parse(s.CronExpr)
		if err == nil {
			n := sched.Next(time.Now())
			nextRun = &n
		} else {
			slog.Warn("invalid cron expression", "schedule_id", s.ID, "cron_expr", s.CronExpr, "err", err)
		}

		if err := store.Schedules.MarkRun(ctx, s.ID, nextRun); err != nil {
			slog.Error("mark schedule run", "schedule_id", s.ID, "err", err)
		}

		slog.Info("scheduled scan enqueued",
			"schedule_id", s.ID,
			"scan_id", scanID,
			"project_id", s.ProjectID,
			"scanner", s.Scanner,
			"next_run", nextRun,
		)
	}
}
