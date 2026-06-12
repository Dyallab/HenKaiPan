package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"aspm/internal/bot"
	"aspm/internal/config"
	"aspm/internal/logger"
)

func main() {
	logger.Init()
	cfg := config.Load()

	log := slog.With("component", "bot-main")

	if !cfg.SlackEnabled {
		log.Info("Slack bot is not configured — set SLACK_APP_TOKEN, SLACK_BOT_TOKEN, API_BASE_URL, and API_TOKEN to enable")
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle SIGINT/SIGTERM for graceful shutdown.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		log.Info("received signal, shutting down", "signal", sig)
		cancel()
	}()

	b := bot.New(cfg)
	if b == nil {
		log.Error("failed to create bot")
		os.Exit(1)
	}

	log.Info("starting Slack bot", "api_base_url", cfg.APIBaseURL)

	if err := b.Run(ctx); err != nil {
		log.Error("bot exited with error", "err", err)
		os.Exit(1)
	}

	log.Info("bot stopped cleanly")
}
