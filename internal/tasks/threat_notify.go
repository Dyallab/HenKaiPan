package tasks

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"aspm/internal/models"
	"aspm/internal/repository"
	"aspm/internal/threats"

	"github.com/hibiken/asynq"
)

// Threat notify + rescan (issue #64 S1/S4).
//
// After SyncThreatIntel persists correlation hits, NotifyForHits fans out
// without any new pipeline: KEV active_threat hits reuse the existing
// webhook:send / email:send queues, unconfirmed hits reuse scan:run for a
// silent corroboration rescan. All enqueue paths mirror scan_run.go and
// scan_scheduler.go (same task types, same MaxRetry/Timeout options).

// ThreatKEVEvent is the webhook event type emitted for KEV active_threat hits.
const ThreatKEVEvent = "threat.kev"

// defaultThreatRescanScanner is the scanner used for silent corroboration rescans of unconfirmed hits.
const defaultThreatRescanScanner = "osv-scanner"

// AdvisoryMeta carries the per-advisory display fields used by notify fan-out.
type AdvisoryMeta struct {
	AdvisoryID  string
	CVEID       string
	Severity    string
	KEV         bool
	AdvisoryURL string
}

// ThreatKEVNotificationPayload is the webhook/email payload for one KEV-confirmed hit.
type ThreatKEVNotificationPayload struct {
	ProjectID   string `json:"project_id"`
	AdvisoryID  string `json:"advisory_id"`
	CVEID       string `json:"cve_id,omitempty"`
	Severity    string `json:"severity,omitempty"`
	PkgName     string `json:"pkg_name"`
	PkgVersion  string `json:"pkg_version,omitempty"`
	AdvisoryURL string `json:"advisory_url"`
}

// ThreatWebhookLister lists enabled webhooks subscribed to threat events.
type ThreatWebhookLister interface {
	ListEnabled(ctx context.Context) ([]models.Webhook, error)
}

// ThreatSettingsReader loads notification settings for email fan-out.
type ThreatSettingsReader interface {
	GetNotificationSettings(ctx context.Context) (*models.NotificationSettings, error)
}

// ThreatScanCreator persists a corroboration rescan and returns its scan ID.
type ThreatScanCreator interface {
	Insert(ctx context.Context, target, scanner, batchID string, projectID *string) (string, error)
}

// ThreatNotifyDeps wires notify fan-out: webhooks, settings, scans, and rescan config.
type ThreatNotifyDeps struct {
	Webhooks             ThreatWebhookLister
	Settings             ThreatSettingsReader
	Scans                ThreatScanCreator
	Email                EmailConfig
	NotificationsEnabled bool
	RescanScanner        string
	ProjectTarget        func(ctx context.Context, projectID string) (target string, ok bool)
}

// DefaultThreatNotifyDeps builds production notify deps from the repository bundle and email config.
func DefaultThreatNotifyDeps(store repository.Stores, email EmailConfig) *ThreatNotifyDeps {
	return &ThreatNotifyDeps{
		Webhooks:             store.Webhooks,
		Settings:             store.Settings,
		Scans:                store.Scans,
		Email:                email,
		NotificationsEnabled: true,
		RescanScanner:        defaultThreatRescanScanner,
		ProjectTarget: func(ctx context.Context, projectID string) (string, bool) {
			p, err := store.Apps.GetProjectByID(ctx, projectID)
			if err != nil || p.RepoURL == nil || strings.TrimSpace(*p.RepoURL) == "" {
				return "", false
			}
			return *p.RepoURL, true
		},
	}
}

// ThreatAdvisoryURL returns the osv.dev URL for an advisory ID.
func ThreatAdvisoryURL(advisoryID string) string {
	return "https://osv.dev/vulnerability/" + advisoryID
}

// NotifyForHits fans out new-or-changed hits: KEV active_threat via webhook/email, unconfirmed via one rescan.
func NotifyForHits(ctx context.Context, queue ThreatEnqueuer, deps ThreatNotifyDeps, projectID string, hits []repository.ThreatHit, advisories map[string]AdvisoryMeta) {
	scanner := deps.RescanScanner
	if strings.TrimSpace(scanner) == "" {
		scanner = defaultThreatRescanScanner
	}
	// Dedupe: one project-wide rescan per call, not one per hit.
	rescanScheduled := false
	for _, h := range hits {
		meta := advisories[h.AdvisoryID]
		switch h.MatchStatus {
		case threats.MatchActiveThreat:
			if !meta.KEV || !deps.NotificationsEnabled {
				continue
			}
			notifyKEVHit(ctx, queue, deps, projectID, h, meta)
		case threats.MatchUnconfirmed, "":
			if rescanScheduled {
				continue
			}
			rescanUnconfirmed(ctx, queue, deps, projectID, scanner)
			rescanScheduled = true
		}
	}
}

// notifyKEVHit enqueues webhook and email notifications for one KEV-confirmed hit.
func notifyKEVHit(ctx context.Context, queue ThreatEnqueuer, deps ThreatNotifyDeps, projectID string, h repository.ThreatHit, meta AdvisoryMeta) {
	if deps.Webhooks == nil && deps.Settings == nil {
		return
	}
	payload := ThreatKEVNotificationPayload{
		ProjectID:   projectID,
		AdvisoryID:  h.AdvisoryID,
		CVEID:       meta.CVEID,
		Severity:    meta.Severity,
		PkgName:     h.PkgName,
		PkgVersion:  h.PkgVersion,
		AdvisoryURL: meta.AdvisoryURL,
	}
	if deps.Webhooks != nil {
		enqueueThreatWebhook(ctx, deps.Webhooks, queue, ThreatKEVEvent, payload)
	}
	if deps.Settings == nil {
		return
	}
	settings, err := deps.Settings.GetNotificationSettings(ctx)
	if err != nil {
		slog.Warn("threat notify: failed to load notification settings", "err", err)
		return
	}
	enqueueThreatEmail(ctx, queue, deps.Email, settings.EmailRecipients,
		threatKEVEmailSubject(payload), buildThreatKEVEmailBody(payload))
}

// rescanUnconfirmed creates and enqueues one silent corroboration scan; missing scans/targets are skipped.
func rescanUnconfirmed(ctx context.Context, queue ThreatEnqueuer, deps ThreatNotifyDeps, projectID, scanner string) {
	if deps.Scans == nil || deps.ProjectTarget == nil {
		return
	}
	target, ok := deps.ProjectTarget(ctx, projectID)
	if !ok || strings.TrimSpace(target) == "" {
		return
	}
	scanID, err := deps.Scans.Insert(ctx, target, scanner, "threat-rescan", &projectID)
	if err != nil {
		slog.Warn("threat rescan: create scan failed", "project_id", projectID, "err", err)
		return
	}
	payload, err := MarshalScanPayload(ScanPayload{
		ScanID:    scanID,
		ProjectID: projectID,
		Target:    target,
		Scanner:   scanner,
	})
	if err != nil {
		slog.Warn("threat rescan: marshal scan payload failed", "scan_id", scanID, "err", err)
		return
	}
	if _, err := queue.EnqueueContext(ctx,
		asynq.NewTask(TypeScanRun, payload),
		asynq.MaxRetry(3),
		asynq.Timeout(30*time.Minute),
	); err != nil {
		slog.Warn("threat rescan: enqueue scan failed", "scan_id", scanID, "err", err)
	}
}

// enqueueThreatWebhook enqueues a webhook:send task per subscribed webhook and returns the count.
func enqueueThreatWebhook(ctx context.Context, webhooks ThreatWebhookLister, queue ThreatEnqueuer, eventType string, payload any) int {
	webhookList, err := webhooks.ListEnabled(ctx)
	if err != nil {
		slog.Warn("threat notify: failed to list enabled webhooks", "err", err)
		return 0
	}
	payloadBytes, err := MarshalWebhookEvent(eventType, payload, time.Now())
	if err != nil {
		slog.Warn("threat notify: failed to marshal webhook payload", "err", err)
		return 0
	}
	enqueued := 0
	for _, webhook := range webhookList {
		subscribed := false
		for _, event := range webhook.Events {
			if event == eventType {
				subscribed = true
				break
			}
		}
		if !subscribed {
			continue
		}
		taskPayload, err := MarshalWebhookPayload(WebhookSendPayload{
			WebhookID: webhook.ID,
			EventType: eventType,
			Payload:   payloadBytes,
		})
		if err != nil {
			slog.Warn("threat notify: failed to marshal webhook task payload", "webhook_id", webhook.ID, "err", err)
			continue
		}
		if _, err := queue.EnqueueContext(ctx, asynq.NewTask(TypeWebhookSend, taskPayload), asynq.MaxRetry(5), asynq.Timeout(30*time.Second)); err != nil {
			slog.Warn("threat notify: failed to enqueue webhook task", "webhook_id", webhook.ID, "err", err)
			continue
		}
		enqueued++
	}
	return enqueued
}

// enqueueThreatEmail enqueues an email:send task for the recipients, returning false when disabled or skipped.
func enqueueThreatEmail(ctx context.Context, queue ThreatEnqueuer, cfg EmailConfig, recipients []string, subject, body string) bool {
	if !cfg.Enabled || len(recipients) == 0 {
		return false
	}
	payload, err := MarshalEmailSendPayload(EmailSendPayload{Subject: subject, Body: body, To: recipients})
	if err != nil {
		slog.Warn("threat notify: marshal email payload failed", "err", err)
		return false
	}
	if _, err := queue.EnqueueContext(ctx, asynq.NewTask(TypeEmailSend, payload), asynq.MaxRetry(5), asynq.Timeout(30*time.Second)); err != nil {
		slog.Warn("threat notify: enqueue email failed", "err", err)
		return false
	}
	return true
}

// threatKEVEmailSubject builds the email subject for a KEV notification, falling back to the advisory ID.
func threatKEVEmailSubject(p ThreatKEVNotificationPayload) string {
	ref := p.CVEID
	if strings.TrimSpace(ref) == "" {
		ref = p.AdvisoryID
	}
	return "KEV threat confirmed: " + ref + " in " + p.PkgName
}

// buildThreatKEVEmailBody renders the plain-text email body for a KEV notification payload.
func buildThreatKEVEmailBody(p ThreatKEVNotificationPayload) string {
	lines := []string{
		"HenKaiPan threat-intel notification",
		"",
		"Event: " + ThreatKEVEvent,
		"Project ID: " + p.ProjectID,
		"Advisory: " + p.AdvisoryID,
		"CVE: " + p.CVEID,
		"Severity: " + strings.ToUpper(p.Severity),
		"Package: " + strings.TrimSpace(p.PkgName+" "+p.PkgVersion),
		"Advisory: " + p.AdvisoryURL,
	}
	return strings.Join(lines, "\n")
}
