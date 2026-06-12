package bot

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/slack-go/slack"
	"github.com/slack-go/slack/socketmode"
)

const (
	actionPrefixAck    = "ack_"
	actionPrefixDismiss = "dismiss_"
	actionPrefixAssign  = "assign_"

	assignModalCallbackPrefix = "assign_finding_"
	assignModalBlockID        = "assign_user_block"
	assignModalActionID       = "user_select"
	assignModalSubmitLabel    = "Assign"
)

// handleBlockActions routes block action interactions to the appropriate handler.
func handleBlockActions(evt *socketmode.Event, bot *Bot) {
	callback, ok := evt.Data.(slack.InteractionCallback)
	if !ok {
		slog.Warn("block action handler: unexpected event data type")
		return
	}

	// Acknowledge the interaction first.
	if err := bot.smClient.Ack(*evt.Request); err != nil {
		slog.Error("block action: ack failed", "err", err)
	}

	log := bot.log.With("user", callback.User.ID, "channel", callback.Channel.ID)

	if len(callback.ActionCallback.BlockActions) == 0 {
		log.Warn("block action: no block actions in callback")
		return
	}

	action := callback.ActionCallback.BlockActions[0]
	actionID := action.ActionID

	log.Info("block action received", "action_id", actionID, "value", action.Value)

	switch {
	case strings.HasPrefix(actionID, actionPrefixAck):
		findingID := strings.TrimPrefix(actionID, actionPrefixAck)
		bot.handleAcknowledge(context.Background(), findingID, action, log)

	case strings.HasPrefix(actionID, actionPrefixDismiss):
		findingID := strings.TrimPrefix(actionID, actionPrefixDismiss)
		bot.handleDismiss(context.Background(), findingID, action, log)

	case strings.HasPrefix(actionID, actionPrefixAssign):
		findingID := strings.TrimPrefix(actionID, actionPrefixAssign)
		bot.handleAssignModal(context.Background(), findingID, callback, log)

	default:
		log.Warn("block action: unknown action ID", "action_id", actionID)
	}
}

// handleViewSubmission routes view submission callbacks from modals.
func handleViewSubmission(evt *socketmode.Event, bot *Bot) {
	callback, ok := evt.Data.(slack.InteractionCallback)
	if !ok {
		slog.Warn("view submission handler: unexpected event data type")
		return
	}

	log := bot.log.With("user", callback.User.ID, "callback_id", callback.View.CallbackID)

	// Checks if this is our assign finding modal.
	if !strings.HasPrefix(callback.View.CallbackID, assignModalCallbackPrefix) {
		log.Debug("view submission: ignoring unknown callback ID")
		_ = bot.smClient.Ack(*evt.Request)
		return
	}

	findingID := strings.TrimPrefix(callback.View.CallbackID, assignModalCallbackPrefix)

	// Extract the selected user from the view state.
	selectedUser, err := extractSelectedUser(callback)
	if err != nil {
		log.Warn("view submission: no user selected", "err", err)
		_ = bot.smClient.Ack(*evt.Request)
		return
	}

	log.Info("assigning finding", "finding_id", findingID, "assignee", selectedUser)

	if err := bot.apiClient.UpdateFindingAssignee(context.Background(), findingID, selectedUser); err != nil {
		log.Error("view submission: failed to assign finding", "err", err)
		_ = bot.smClient.Ack(*evt.Request)
		return
	}

	// Acknowledge with a clear response to close the modal.
	_ = bot.smClient.Ack(*evt.Request, slack.NewClearViewSubmissionResponse())
}

// handleAcknowledge marks a finding as in_review.
func (bot *Bot) handleAcknowledge(ctx context.Context, findingID string, action *slack.BlockAction, log *slog.Logger) {
	log.Info("acknowledging finding", "finding_id", findingID)
	if err := bot.apiClient.UpdateFindingStatus(ctx, findingID, "in_review"); err != nil {
		log.Error("failed to acknowledge finding", "err", err)
		return
	}
	log.Info("finding acknowledged successfully", "finding_id", findingID)
}

// handleDismiss marks a finding as accepted_risk.
func (bot *Bot) handleDismiss(ctx context.Context, findingID string, action *slack.BlockAction, log *slog.Logger) {
	log.Info("dismissing finding", "finding_id", findingID)
	if err := bot.apiClient.UpdateFindingStatus(ctx, findingID, "accepted_risk"); err != nil {
		log.Error("failed to dismiss finding", "err", err)
		return
	}
	log.Info("finding dismissed successfully", "finding_id", findingID)
}

// handleAssignModal opens a Slack modal with a user select dropdown for assigning a finding.
func (bot *Bot) handleAssignModal(ctx context.Context, findingID string, callback slack.InteractionCallback, log *slog.Logger) {
	modalView := buildAssignModal(findingID)
	_, err := bot.smClient.OpenView(callback.TriggerID, modalView)
	if err != nil {
		log.Error("failed to open assign modal", "err", err)
		return
	}
	log.Info("assign modal opened", "finding_id", findingID)
}

// buildAssignModal creates a ModalViewRequest with a user select dropdown.
func buildAssignModal(findingID string) slack.ModalViewRequest {
	userSelect := slack.NewOptionsSelectBlockElement(
		slack.OptTypeUser,
		slack.NewTextBlockObject(slack.PlainTextType, "Select a user", false, false),
		assignModalActionID,
	)

	inputBlock := slack.NewInputBlock(
		assignModalBlockID,
		slack.NewTextBlockObject(slack.PlainTextType, "Assign to", false, false),
		nil,
		userSelect,
	)

	return slack.ModalViewRequest{
		Type:       slack.VTModal,
		Title:      slack.NewTextBlockObject(slack.PlainTextType, "Assign Finding", false, false),
		Submit:     slack.NewTextBlockObject(slack.PlainTextType, assignModalSubmitLabel, false, false),
		Close:      slack.NewTextBlockObject(slack.PlainTextType, "Cancel", false, false),
		CallbackID: assignModalCallbackPrefix + findingID,
		Blocks: slack.Blocks{BlockSet: []slack.Block{
			slack.NewSectionBlock(
				slack.NewTextBlockObject(slack.MarkdownType, fmt.Sprintf("Assign finding `%s` to a user:", findingID), false, false),
				nil, nil,
			),
			inputBlock,
		}},
	}
}

// extractSelectedUser extracts the selected user ID from a view submission callback.
func extractSelectedUser(callback slack.InteractionCallback) (string, error) {
	if callback.View.State == nil {
		return "", fmt.Errorf("view state is nil")
	}
	values := callback.View.State.Values
	if values == nil {
		return "", fmt.Errorf("view state values is nil")
	}
	block, ok := values[assignModalBlockID]
	if !ok {
		return "", fmt.Errorf("block %q not found in view state", assignModalBlockID)
	}
	action, ok := block[assignModalActionID]
	if !ok {
		return "", fmt.Errorf("action %q not found in block %q", assignModalActionID, assignModalBlockID)
	}
	if action.SelectedUser == "" {
		return "", fmt.Errorf("no user selected")
	}
	return action.SelectedUser, nil
}
