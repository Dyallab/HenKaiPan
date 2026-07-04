package main

import (
	"context"
	"log/slog"
	"os"

	"aspm/internal/agents"
	"aspm/internal/config"
	"aspm/internal/db"
	"aspm/internal/logger"
	"aspm/internal/queue"
	"aspm/internal/repository"
	"aspm/internal/tasks"

	"github.com/hibiken/asynq"
)

func main() {
	logger.Init()
	cfg := config.Load()

	pool := db.Connect(cfg.DatabaseURL)
	defer pool.Close()

	store := repository.NewPostgresStores(pool)

	if n, err := store.Scans.RecoverStuck(context.Background()); err == nil && n > 0 {
		slog.Info("recovered stuck scans", "count", n)
	}

	// queue client for enqueueing sub-tasks (e.g. agent:validate after scan)
	queueClient := queue.NewClient(cfg.RedisAddr)
	defer queueClient.Close()

	srv := queue.NewServer(cfg.RedisAddr, 5)

	mux := asynq.NewServeMux()
	mux.HandleFunc(tasks.TypeScanRun, tasks.HandleScan(store.Scans, store.Findings, store.Policies, queueClient))

	if cfg.AnthropicAPIKey != "" {
		validator, err := agents.NewValidator(cfg.AnthropicAPIKey, store.Agents, store.Findings)
		if err != nil {
			slog.Error("init validator agent", "err", err)
			os.Exit(1)
		}
		mux.HandleFunc(tasks.TypeAgentValidate, tasks.HandleAgentValidate(validator))
		slog.Info("agent:validate handler registered")
	} else {
		slog.Warn("ANTHROPIC_API_KEY not set — agent:validate tasks will not be processed")
	}

	slog.Info("worker started, waiting for tasks")
	if err := srv.Run(mux); err != nil {
		slog.Error("worker failed", "err", err)
		os.Exit(1)
	}
}
