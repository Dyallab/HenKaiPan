package bot

import (
	"context"
	"log/slog"

	"aspm/internal/config"

	"github.com/slack-go/slack"
	"github.com/slack-go/slack/socketmode"
)

// Bot represents the Slack Socket Mode bot that handles interactive messages.
type Bot struct {
	smClient  *socketmode.Client
	apiClient *APIClient
	log       *slog.Logger
}

// New creates a new Bot from the application config.
// Returns nil if Slack is not configured (caller should check cfg.SlackEnabled).
func New(cfg *config.Config) *Bot {
	slackClient := slack.New(
		cfg.SlackBotToken,
		slack.OptionAppLevelToken(cfg.SlackAppToken),
	)

	smClient := socketmode.New(
		slackClient,
		socketmode.OptionLog(slog.NewLogLogger(slog.NewJSONHandler(nil, nil), slog.LevelDebug)),
	)

	apiClient := NewAPIClient(cfg.APIBaseURL, cfg.APIToken)

	log := slog.With("component", "slack-bot")

	return &Bot{
		smClient:  smClient,
		apiClient: apiClient,
		log:       log,
	}
}

// Run starts the Socket Mode event loop and blocks until the context is cancelled.
func (bot *Bot) Run(ctx context.Context) error {
	bot.log.Info("starting Slack Socket Mode client")

	// Start the event loop in a goroutine
	go bot.eventLoop(ctx)

	// Block on the socket mode client run, which reconnects automatically.
	// When ctx is cancelled, RunContext returns and we exit cleanly.
	if err := bot.smClient.RunContext(ctx); err != nil {
		if ctx.Err() != nil {
			bot.log.Info("Slack bot shutting down gracefully")
			return nil
		}
		bot.log.Error("Slack Socket Mode client exited with error", "err", err)
		return err
	}

	return nil
}

// eventLoop reads events from the socket mode client's Events channel and dispatches them.
func (bot *Bot) eventLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			bot.log.Info("event loop: context cancelled, shutting down")
			return
		case evt, ok := <-bot.smClient.Events:
			if !ok {
				bot.log.Info("event loop: events channel closed")
				return
			}
			bot.handleEvent(ctx, evt)
		}
	}
}

// handleEvent dispatches a single socket mode event to the appropriate handler.
func (bot *Bot) handleEvent(ctx context.Context, evt socketmode.Event) {
	switch evt.Type {
	case socketmode.EventTypeConnecting:
		bot.log.Info("connecting to Slack...")
	case socketmode.EventTypeConnected:
		bot.log.Info("connected to Slack")
	case socketmode.EventTypeConnectionError:
		bot.log.Warn("connection error, retrying...")
	case socketmode.EventTypeHello:
		bot.log.Debug("Slack hello received")
	case socketmode.EventTypeInteractive:
		bot.dispatchInteraction(evt)
	case socketmode.EventTypeEventsAPI:
		// Events API not handled yet — just acknowledge.
		if evt.Request != nil {
			_ = bot.smClient.Ack(*evt.Request)
		}
	case socketmode.EventTypeSlashCommand:
		// Slash commands not handled yet — just acknowledge.
		if evt.Request != nil {
			_ = bot.smClient.Ack(*evt.Request)
		}
	default:
		bot.log.Debug("unhandled event type", "type", evt.Type)
	}
}

// dispatchInteraction routes interactive events based on the interaction type.
func (bot *Bot) dispatchInteraction(evt socketmode.Event) {
	callback, ok := evt.Data.(slack.InteractionCallback)
	if !ok {
		bot.log.Warn("interactive event: unexpected data type")
		if evt.Request != nil {
			_ = bot.smClient.Ack(*evt.Request)
		}
		return
	}

	switch callback.Type {
	case slack.InteractionTypeBlockActions:
		handleBlockActions(&evt, bot)
	case slack.InteractionTypeViewSubmission:
		handleViewSubmission(&evt, bot)
	case slack.InteractionTypeViewClosed:
		// Acknowledge view closed events to prevent warnings.
		if evt.Request != nil {
			_ = bot.smClient.Ack(*evt.Request)
		}
	default:
		bot.log.Debug("unhandled interaction type", "type", callback.Type)
		if evt.Request != nil {
			_ = bot.smClient.Ack(*evt.Request)
		}
	}
}
