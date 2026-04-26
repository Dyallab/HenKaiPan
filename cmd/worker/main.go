package main

import (
	"context"
	"log/slog"
	"os"
	"time"

	"aspm/internal/ai"
	"aspm/internal/config"
	"aspm/internal/db"
	"aspm/internal/findings"
	"aspm/internal/logger"
	"aspm/internal/queue"
	"aspm/internal/repository"
	"aspm/internal/tasks"

	"github.com/hibiken/asynq"
)

func main() {
	logger.Init()
	cfg := config.Load()
	ai.Init(cfg)

	pool := db.Connect(cfg.DatabaseURL)
	defer pool.Close()

	store := repository.NewPostgresStores(pool)

	if n, err := store.Scans.RecoverStuck(context.Background()); err == nil && n > 0 {
		slog.Info("recovered stuck scans", "count", n)
	}

	// queue client for enqueueing sub-tasks (e.g. agent:validate after scan)
	queueClient := queue.NewClient(cfg.RedisAddr)
	defer queueClient.Close()
	notifications := tasks.NewNotificationConfig(cfg)

	srv := queue.NewServer(cfg.RedisAddr, 5)

	mux := asynq.NewServeMux()
	mux.HandleFunc(tasks.TypeScanRun, tasks.HandleScan(store.Scans, store.Findings, store.Policies, store.Webhooks, store.Settings, queueClient, notifications))
	mux.HandleFunc(tasks.TypeWebhookSend, tasks.HandleWebhookSend(store.Webhooks))
	mux.HandleFunc(tasks.TypeEmailSend, tasks.HandleEmailSend(notifications.Email))
	tasks.StartSLABreachMonitor(context.Background(), store.Settings, store.Findings, store.Webhooks, queueClient, notifications, 15*time.Minute)

	// Register AI agent handlers if configured
	if cfg.ValidationConfig.IsConfigured {
		validator := findings.NewValidationAgent(store.Agents, store.Findings)
		mux.HandleFunc(tasks.TypeFindingValidate, tasks.HandleFindingValidate(validator))
		slog.Info("agent:validate handler registered", "provider", cfg.ValidationConfig.Name, "model", cfg.ValidationConfig.Model)
	} else {
		slog.Warn("AI validation not configured — agent:validate handler will not be registered")
	}

	if cfg.SummaryConfig.IsConfigured {
		summaryAgent := findings.NewSummaryAgent(store.Findings, cfg.SummaryConfig.Model)
		mux.HandleFunc(tasks.TypeFindingSummarize, tasks.HandleFindingSummarize(summaryAgent))
		slog.Info("agent:summarize handler registered", "provider", cfg.SummaryConfig.Name, "model", cfg.SummaryConfig.Model)
	} else {
		slog.Warn("AI summary not configured — agent:summarize handler will not be registered")
	}

	slog.Info("worker started, waiting for tasks")
	if err := srv.Run(mux); err != nil {
		slog.Error("worker failed", "err", err)
		os.Exit(1)
	}
}
