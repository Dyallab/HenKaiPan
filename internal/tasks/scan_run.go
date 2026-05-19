package tasks

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"aspm/internal/ai"
	"aspm/internal/config"
	"aspm/internal/repository"
	"aspm/internal/scanner"

	"github.com/hibiken/asynq"
)

var scannerExecutor = scanner.NewExecutor()

const maxLogBytes = 100 * 1024 // 100 KB per stream

type NotificationConfig struct {
	FrontendURL string
	Email       EmailConfig
}

func NewNotificationConfig(cfg *config.Config) NotificationConfig {
	return NotificationConfig{
		FrontendURL: cfg.FrontendURL,
		Email: EmailConfig{
			Host:     cfg.SMTPHost,
			Port:     cfg.SMTPPort,
			Username: cfg.SMTPUsername,
			Password: cfg.SMTPPassword,
			From:     cfg.SMTPFrom,
			Enabled:  cfg.EmailEnabled,
		},
	}
}

type runResult struct {
	stdout []byte
	log    string
	err    error
}

func computeFingerprint(scanner, ruleID, filePath string, lineStart int) string {
	h := sha256.Sum256([]byte(scanner + ":" + ruleID + ":" + filePath + ":" + strconv.Itoa(lineStart)))
	return hex.EncodeToString(h[:])
}

// HandleScan runs a queued scan job for any configured scanner.
func HandleScan(scans repository.ScanRepository, findings repository.FindingRepository, policies repository.PolicyRepository, webhooks repository.WebhookRepository, settings repository.SettingsRepository, apps repository.AppRepository, queue *asynq.Client, notifications NotificationConfig) asynq.HandlerFunc {
	return func(ctx context.Context, t *asynq.Task) error {
		p, err := UnmarshalScanPayload(t.Payload())
		if err != nil {
			return err
		}

		log := slog.With("scan_id", p.ScanID, "scanner", p.Scanner, "target", p.Target, "project_id", p.ProjectID)

		log.Info("scan task received")

		sc, ok := scanner.Get(p.Scanner)
		if !ok {
			return fmt.Errorf("unknown scanner: %s", p.Scanner)
		}

		if err := scans.MarkRunning(ctx, p.ScanID); err != nil {
			return fmt.Errorf("update status: %w", err)
		}

		log.Info("scan started")

		var result runResult

		switch sc.TargetType {
		case scanner.TargetGit:
			dir, cloneLog, err := cloneRepo(ctx, apps, p.ProjectID, p.Target, p.ScanID)
			if err != nil {
				scans.MarkFailed(ctx, p.ScanID, err.Error(), cloneLog)
				enqueueScanNotification(ctx, scans, settings, webhooks, queue, notifications, p.ScanID, "scan.failed", err.Error(), time.Now())
				log.Error("clone failed", "err", err)
				return err
			}
			defer os.RemoveAll(dir)
			execResult := scannerExecutor.RunScanner(ctx, sc, dir)
			result = runResult{
				stdout: execResult.Stdout,
				log:    execResult.Log,
				err:    execResult.Err,
			}

		case scanner.TargetURL:
			execResult := runScannerURL(sc, p.Target)
			result = runResult{
				stdout: execResult.stdout,
				log:    execResult.log,
				err:    execResult.err,
			}
		}

		if result.err != nil && len(result.stdout) == 0 {
			scans.MarkFailed(ctx, p.ScanID, result.err.Error(), result.log)
			enqueueScanNotification(ctx, scans, settings, webhooks, queue, notifications, p.ScanID, "scan.failed", result.err.Error(), time.Now())
		log.Error("scanner execution failed", "err", result.err)
		return fmt.Errorf("%s scanner execution: %w", sc.Name, result.err)
		}

		parsed, parseErr := sc.Parse(result.stdout)
		if parseErr != nil {
			log.Warn("parse warning", "err", parseErr)
		}

		now := time.Now()
		inserted := 0
		for _, f := range parsed {
			sla := slaDeadlineFor(normalizeSeverity(f.Severity), now)
			var cveID, cweID *string
			if f.CVEID != "" {
				cveID = &f.CVEID
			}
			if f.CWEID != "" {
				cweID = &f.CWEID
			}
			norm := normalizeSeverity(f.Severity)

			suppressed, _ := policies.IsSuppressed(ctx, sc.Name, f.RuleID, f.FilePath)

			fingerprint := computeFingerprint(sc.Name, f.RuleID, f.FilePath, f.LineStart)

			findingID, err := findings.Insert(ctx, repository.FindingInsert{
				ScanID: p.ScanID, Scanner: sc.Name, RuleID: f.RuleID,
				Title: f.Title, Description: f.Description,
				Severity: norm, FilePath: f.FilePath,
				LineStart: f.LineStart, LineEnd: f.LineEnd,
				CodeSnippet: f.CodeSnippet, Raw: f.Raw,
				SLADeadline: sla, CVEID: cveID, CWEID: cweID,
				Suppressed: suppressed,
				SecretHash: f.SecretHash,
				ProjectID:  p.ProjectID,
				Fingerprint: fingerprint,
			})
			if err != nil {
				log.Error("insert finding failed", "rule_id", f.RuleID, "err", err)
				continue
			}
			if findingID == "" {
				continue
			}
			inserted++
			if err := findings.RefreshBatchCorrelation(ctx, findingID); err != nil {
				log.Warn("refresh batch correlation failed", "finding_id", findingID, "err", err)
			}
			if strings.TrimSpace(f.Description) == "" {
				// Auto-summary disabled: summaries are only generated on explicit user request.
				// To re-enable, uncomment: enqueueFindingSummary(ctx, findings, queue, findingID)
				_ = findingID
			}
			if !suppressed {
				applyPolicies(ctx, policies, findingID, sc.Name, norm, f.RuleID, f.FilePath)
			}

			enqueueFindingNotification(ctx, settings, webhooks, queue, notifications, FindingCreatedPayload{
				FindingID:   findingID,
				Repository:  p.Target,
				Severity:    norm,
				Title:       f.Title,
				RuleID:      f.RuleID,
				FilePath:    f.FilePath,
				Line:        f.LineStart,
				Scanner:     sc.Name,
				Description: f.Description,
				CreatedAt:   now,
			})
		}

		log.Info("scan completed", "findings_parsed", len(parsed), "findings_inserted", inserted)

		var exitErrStr *string
		if result.err != nil {
			s := result.err.Error()
			exitErrStr = &s
		}
		if err := scans.MarkCompleted(ctx, p.ScanID, result.log, exitErrStr); err != nil {
			return err
		}
		enqueueScanNotification(ctx, scans, settings, webhooks, queue, notifications, p.ScanID, "scan.completed", derefErr(exitErrStr), time.Now())
		return nil
	}
}

// ── helpers ──────────────────────────────────────────────────────────────────

func cloneRepo(ctx context.Context, apps repository.AppRepository, projectID, url, scanID string) (dir string, execLog string, err error) {
	dir = filepath.Join(os.TempDir(), "aspm-scan-"+scanID)

	slog.Info("cloneRepo called", "project_id", projectID, "url", url, "scan_id", scanID)

	if _, err := os.Stat(dir); err == nil {
		slog.Info("removing existing scan directory from previous attempt", "dir", dir)
		if rmErr := os.RemoveAll(dir); rmErr != nil {
			slog.Warn("failed to remove existing directory", "dir", dir, "err", rmErr)
		}
	}

	var token string
	if projectID != "" {
		var err error
		token, err = apps.GetProjectGitHubToken(ctx, projectID)
		if err != nil {
			slog.Warn("failed to get project github token", "project_id", projectID, "err", err)
		} else if token != "" {
			slog.Info("github token retrieved from project", "project_id", projectID, "token_len", len(token))
		}
	}
	if token == "" {
		slog.Warn("no github token available, proceeding without auth")
	}

	cloneURL := url
	var branch string
	if idx := strings.Index(cloneURL, "#"); idx != -1 {
		branch = cloneURL[idx+1:]
		cloneURL = cloneURL[:idx]
	}

	start := time.Now()

	// Pull request refs (refs/pull/N/*) are GitHub-internal refs that don't
	// exist in the remote. Clone normally, then fetch the specific ref.
	if strings.HasPrefix(branch, "refs/pull/") {
		dir, execLog, err := cloneWithPullRef(ctx, cloneURL, branch, token, dir, start)
		return dir, execLog, err
	}

	args := []string{"clone", "--depth=50"}
	if branch != "" {
		args = append(args, "--branch", branch)
	}

	// Use http.extraHeader to pass token via Authorization header instead of
	// embedding it in the URL. This prevents token leakage into logs, ps output,
	// and git config files.
	if token != "" {
		args = append([]string{"-c", "http.extraHeader=Authorization: token " + token}, args...)
	}

	args = append(args, cloneURL, dir)
	cmd := exec.CommandContext(ctx, "git", args...)
	out, cloneErr := cmd.CombinedOutput()
	execLog = buildSimpleLog("git clone --depth=50 "+branchStr(branch)+" "+cloneURL, out, nil, cloneErr, time.Since(start))
	if cloneErr != nil {
		if rmErr := os.RemoveAll(dir); rmErr != nil {
			slog.Warn("failed to remove partial clone directory", "dir", dir, "err", rmErr)
		}
		return "", execLog, fmt.Errorf("git clone: %w\n%s", cloneErr, out)
	}
	return dir, execLog, nil
}

// cloneWithPullRef clones a repo and fetchs a GitHub pull request ref.
// refs/pull/N/* are internal GitHub refs that cannot be fetched via --branch.
func cloneWithPullRef(ctx context.Context, cloneURL, branch, token, dir string, start time.Time) (string, string, error) {
	// Step 1: Clone without --branch
	cloneArgs := []string{"clone", "--depth=50", cloneURL, dir}
	if token != "" {
		cloneArgs = append([]string{"-c", "http.extraHeader=Authorization: token " + token}, cloneArgs...)
	}
	cmd := exec.CommandContext(ctx, "git", cloneArgs...)
	out, cloneErr := cmd.CombinedOutput()
	if cloneErr != nil {
		if rmErr := os.RemoveAll(dir); rmErr != nil {
			slog.Warn("failed to remove partial clone directory", "dir", dir, "err", rmErr)
		}
		log := buildSimpleLog("git clone --depth=50 "+cloneURL, out, nil, cloneErr, time.Since(start))
		return "", log, fmt.Errorf("git clone: %w\n%s", cloneErr, out)
	}

	// Step 2: Fetch the pull request ref
	refName := "hkp-pr-ref"
	fetchArgs := []string{"-C", dir, "fetch", "origin", branch + ":" + refName, "--depth=1"}
	if token != "" {
		fetchArgs = append([]string{"-c", "http.extraHeader=Authorization: token " + token}, fetchArgs...)
	}
	fetchCmd := exec.CommandContext(ctx, "git", fetchArgs...)
	fetchOut, fetchErr := fetchCmd.CombinedOutput()
	if fetchErr != nil {
		if rmErr := os.RemoveAll(dir); rmErr != nil {
			slog.Warn("failed to remove clone directory after fetch failure", "dir", dir, "err", rmErr)
		}
		log := buildSimpleLog("git fetch origin "+branch, fetchOut, nil, fetchErr, time.Since(start))
		return "", log, fmt.Errorf("git fetch %s: %w\n%s", branch, fetchErr, fetchOut)
	}

	// Step 3: Checkout the fetched ref
	checkoutArgs := []string{"-C", dir, "checkout", refName}
	checkoutCmd := exec.CommandContext(ctx, "git", checkoutArgs...)
	checkoutOut, checkoutErr := checkoutCmd.CombinedOutput()
	if checkoutErr != nil {
		if rmErr := os.RemoveAll(dir); rmErr != nil {
			slog.Warn("failed to remove clone directory after checkout failure", "dir", dir, "err", rmErr)
		}
		log := buildSimpleLog("git checkout "+refName, checkoutOut, nil, checkoutErr, time.Since(start))
		return "", log, fmt.Errorf("git checkout %s: %w\n%s", refName, checkoutErr, checkoutOut)
	}

	log := buildSimpleLog("git clone + fetch "+branch, nil, nil, nil, time.Since(start))
	return dir, log, nil
}

func branchStr(b string) string {
	if b != "" {
		return "--branch " + b
	}
	return ""
}

func runScannerURL(sc scanner.Scanner, target string) runResult {
	execResult := scannerExecutor.RunScanner(context.Background(), sc, target)
	return runResult{
		stdout: execResult.Stdout,
		log:    execResult.Log,
		err:    execResult.Err,
	}
}

func buildSimpleLog(cmdStr string, stdout, stderr []byte, err error, elapsed time.Duration) string {
	var b strings.Builder

	b.WriteString("$ " + cmdStr + "\n")
	fmt.Fprintf(&b, "# elapsed: %s\n", elapsed.Round(time.Millisecond))

	if err != nil {
		fmt.Fprintf(&b, "# exit: %s\n", err)
	} else {
		b.WriteString("# exit: 0\n")
	}

	if len(stdout) > 0 {
		b.WriteString("\n─── STDOUT ────────────────────────────────\n")
		b.Write(truncate(stdout, maxLogBytes))
		if len(stdout) > maxLogBytes {
			fmt.Fprintf(&b, "\n[... truncated %d bytes ...]", len(stdout)-maxLogBytes)
		}
	}

	if len(stderr) > 0 {
		b.WriteString("\n─── STDERR ────────────────────────────────\n")
		b.Write(truncate(stderr, maxLogBytes))
		if len(stderr) > maxLogBytes {
			fmt.Fprintf(&b, "\n[... truncated %d bytes ...]", len(stderr)-maxLogBytes)
		}
	}

	return b.String()
}

func truncate(b []byte, max int) []byte {
	if len(b) <= max {
		return b
	}
	return b[:max]
}

var validSeverities = map[string]bool{
	"critical": true, "high": true, "medium": true, "low": true, "info": true,
}

func normalizeSeverity(s string) string {
	if validSeverities[s] {
		return s
	}
	return "info"
}

func enqueueAgentValidate(ctx context.Context, queue *asynq.Client, findingID string) {
	payload, err := MarshalFindingValidatePayload(FindingValidatePayload{FindingID: findingID})
	if err != nil {
		slog.Warn("marshal agent:validate payload failed", "finding_id", findingID, "err", err)
		return
	}
	if _, err := queue.EnqueueContext(ctx, asynq.NewTask(TypeFindingValidate, payload)); err != nil {
		slog.Warn("enqueue agent:validate failed", "finding_id", findingID, "err", err)
	}
}

func enqueueFindingSummary(ctx context.Context, findings repository.FindingRepository, queue *asynq.Client, findingID string) {
	prepared, err := findings.PrepareAISummary(ctx, findingID)
	if err != nil {
		slog.Warn("prepare ai summary failed", "finding_id", findingID, "err", err)
		return
	}
	if prepared == nil || !prepared.ShouldEnqueue {
		return
	}
	payload, err := MarshalFindingSummarizePayload(FindingSummarizePayload{FindingID: findingID})
	if err != nil {
		slog.Warn("marshal agent:summarize payload failed", "finding_id", findingID, "err", err)
		return
	}
	if _, err := queue.EnqueueContext(ctx, asynq.NewTask(TypeFindingSummarize, payload)); err != nil {
		slog.Warn("enqueue agent:summarize failed", "finding_id", findingID, "err", err)
	}
}

func slaDeadlineFor(severity string, now time.Time) *time.Time {
	var d time.Duration
	switch severity {
	case "critical":
		d = 24 * time.Hour
	case "high":
		d = 72 * time.Hour
	case "medium":
		d = 30 * 24 * time.Hour
	case "low":
		d = 90 * 24 * time.Hour
	default:
		return nil
	}
	t := now.Add(d)
	return &t
}

type FindingCreatedPayload struct {
	FindingID   string    `json:"finding_id"`
	Repository  string    `json:"repository"`
	Severity    string    `json:"severity"`
	Title       string    `json:"title"`
	RuleID      string    `json:"rule_id"`
	FilePath    string    `json:"file_path"`
	Line        int       `json:"line"`
	Scanner     string    `json:"scanner"`
	Description string    `json:"description,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	AISummary   string    `json:"ai_summary,omitempty"`
}

type ScanNotificationPayload struct {
	ScanID       string    `json:"scan_id"`
	Target       string    `json:"target"`
	Scanner      string    `json:"scanner"`
	Status       string    `json:"status"`
	FindingCount int       `json:"finding_count"`
	Error        string    `json:"error,omitempty"`
	CompletedAt  time.Time `json:"completed_at"`
}

func enqueueFindingNotification(ctx context.Context, settings repository.SettingsRepository, webhooks repository.WebhookRepository, queue *asynq.Client, notifications NotificationConfig, payload FindingCreatedPayload) {
	notificationSettings, err := settings.GetNotificationSettings(ctx)
	if err != nil {
		slog.Warn("failed to load notification settings", "err", err)
		return
	}
	nc := ai.NotificationContext{
		Severity:    payload.Severity,
		Title:       payload.Title,
		RuleID:      payload.RuleID,
		Scanner:     payload.Scanner,
		Description: payload.Description,
		FilePath:    payload.FilePath,
		Line:        payload.Line,
		Repository:  payload.Repository,
		EventType:   "finding.created",
	}
	payload.AISummary = ai.GenerateNotificationSummary(ctx, nc)
	recipients := notificationSettings.EmailRecipients
	switch payload.Severity {
	case "critical":
		if notificationSettings.AlertCritical {
			enqueueWebhookEvent(ctx, webhooks, queue, "finding.critical", payload)
			enqueueEmailEvent(ctx, queue, notifications.Email, recipients, "Critical finding detected", buildFindingEmailBody("finding.critical", payload))
		}
	case "high":
		if notificationSettings.AlertHigh {
			enqueueWebhookEvent(ctx, webhooks, queue, "finding.high", payload)
			enqueueEmailEvent(ctx, queue, notifications.Email, recipients, "High severity finding detected", buildFindingEmailBody("finding.high", payload))
		}
	}
}

func enqueueScanNotification(ctx context.Context, scans repository.ScanRepository, settings repository.SettingsRepository, webhooks repository.WebhookRepository, queue *asynq.Client, notifications NotificationConfig, scanID, eventType, errorMessage string, now time.Time) {
	notificationSettings, err := settings.GetNotificationSettings(ctx)
	if err != nil {
		slog.Warn("failed to load notification settings", "err", err)
		return
	}
	if eventType == "scan.completed" && !notificationSettings.AlertScanComplete {
		return
	}
	if eventType == "scan.failed" && !notificationSettings.AlertScanFailed {
		return
	}
	scan, err := scans.Get(ctx, scanID)
	if err != nil {
		slog.Warn("failed to load scan for notification", "scan_id", scanID, "err", err)
		return
	}
	payload := ScanNotificationPayload{
		ScanID:       scan.ID,
		Target:       scan.Target,
		Scanner:      scan.Scanner,
		Status:       string(scan.Status),
		FindingCount: scan.FindingCount,
		Error:        errorMessage,
		CompletedAt:  now,
	}
	recipients := notificationSettings.EmailRecipients
	enqueueWebhookEvent(ctx, webhooks, queue, eventType, payload)
	enqueueEmailEvent(ctx, queue, notifications.Email, recipients, scanEmailSubject(eventType), buildScanEmailBody(eventType, payload))
}

func enqueueWebhookEvent(ctx context.Context, webhooks repository.WebhookRepository, queue *asynq.Client, eventType string, payload any) int {
	webhookList, err := webhooks.ListEnabled(ctx)
	if err != nil {
		slog.Warn("failed to list enabled webhooks", "err", err)
		return 0
	}

	payloadBytes, err := MarshalWebhookEvent(eventType, payload, time.Now())
	if err != nil {
		slog.Warn("failed to marshal webhook payload", "err", err)
		return 0
	}

	enqueued := 0
	for _, webhook := range webhookList {
		containsEvent := false
		for _, event := range webhook.Events {
			if event == eventType || (event == "finding.created" && (eventType == "finding.critical" || eventType == "finding.high")) {
				containsEvent = true
				break
			}
		}
		if !containsEvent {
			continue
		}

		taskPayload, err := MarshalWebhookPayload(WebhookSendPayload{
			WebhookID: webhook.ID,
			EventType: eventType,
			Payload:   payloadBytes,
		})
		if err != nil {
			slog.Warn("failed to marshal webhook task payload", "webhook_id", webhook.ID, "err", err)
			continue
		}

		if _, err := queue.EnqueueContext(ctx, asynq.NewTask(TypeWebhookSend, taskPayload), asynq.MaxRetry(5), asynq.Timeout(30*time.Second)); err != nil {
			slog.Warn("failed to enqueue webhook task", "webhook_id", webhook.ID, "err", err)
			continue
		}
		enqueued++

		slog.Info("enqueued webhook delivery", "webhook_id", webhook.ID, "event_type", eventType)
	}
	return enqueued
}

func enqueueEmailEvent(ctx context.Context, queue *asynq.Client, cfg EmailConfig, recipients []string, subject, body string) bool {
	if !cfg.Enabled || len(recipients) == 0 {
		return false
	}
	payload, err := MarshalEmailSendPayload(EmailSendPayload{Subject: subject, Body: body, To: recipients})
	if err != nil {
		slog.Warn("marshal email payload failed", "err", err)
		return false
	}
	if _, err := queue.EnqueueContext(ctx, asynq.NewTask(TypeEmailSend, payload), asynq.MaxRetry(5), asynq.Timeout(30*time.Second)); err != nil {
		slog.Warn("enqueue email failed", "err", err)
		return false
	}
	return true
}

func derefErr(err *string) string {
	if err == nil {
		return ""
	}
	return *err
}

func StartSLABreachMonitor(ctx context.Context, settings repository.SettingsRepository, findings repository.FindingRepository, webhooks repository.WebhookRepository, queue *asynq.Client, notifications NotificationConfig, interval time.Duration) {
	if interval <= 0 {
		interval = 15 * time.Minute
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		CheckSLABreaches(ctx, settings, findings, webhooks, queue, notifications)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				CheckSLABreaches(ctx, settings, findings, webhooks, queue, notifications)
			}
		}
	}()
}

func CheckSLABreaches(ctx context.Context, settings repository.SettingsRepository, findings repository.FindingRepository, webhooks repository.WebhookRepository, queue *asynq.Client, notifications NotificationConfig) {
	notificationSettings, err := settings.GetNotificationSettings(ctx)
	if err != nil {
		slog.Warn("failed to load notification settings for sla breach monitor", "err", err)
		return
	}
	if !notificationSettings.AlertSLABreach {
		return
	}
	recipients := notificationSettings.EmailRecipients
	breaches, err := findings.ListPendingSLABreaches(ctx, 100)
	if err != nil {
		slog.Warn("failed to list pending sla breaches", "err", err)
		return
	}
	if len(breaches) == 0 {
		return
	}
	marked := make([]string, 0, len(breaches))
	for _, breach := range breaches {
		fc := ai.NotificationContext{
			Severity:   breach.Severity,
			Title:      breach.Title,
			RuleID:     breach.RuleID,
			Scanner:    breach.Scanner,
			Repository: breach.Repository,
			FilePath:   breach.FilePath,
			Line:       breach.Line,
			EventType:  "finding.sla_breach",
		}
		payload := SLABreachPayload{
			FindingID:   breach.FindingID,
			ScanID:      breach.ScanID,
			Repository:  breach.Repository,
			Severity:    breach.Severity,
			Title:       breach.Title,
			RuleID:      breach.RuleID,
			FilePath:    breach.FilePath,
			Line:        breach.Line,
			Scanner:     breach.Scanner,
			SLADeadline: breach.SLADeadline,
			CreatedAt:   breach.CreatedAt,
			AISummary:   ai.GenerateNotificationSummary(ctx, fc),
		}
		webhookCount := enqueueWebhookEvent(ctx, webhooks, queue, "finding.sla_breach", payload)
		emailQueued := enqueueEmailEvent(ctx, queue, notifications.Email, recipients, "SLA breach detected", buildSLABreachEmailBody(payload))
		if webhookCount > 0 || emailQueued {
			marked = append(marked, breach.FindingID)
		}
	}
	if err := findings.MarkSLABreachAttempted(ctx, marked); err != nil {
		slog.Warn("failed to mark sla breaches as attempted", "err", err)
	}
}

type SLABreachPayload struct {
	FindingID   string    `json:"finding_id"`
	ScanID      string    `json:"scan_id"`
	Repository  string    `json:"repository"`
	Severity    string    `json:"severity"`
	Title       string    `json:"title"`
	RuleID      string    `json:"rule_id"`
	FilePath    string    `json:"file_path"`
	Line        int       `json:"line"`
	Scanner     string    `json:"scanner"`
	SLADeadline time.Time `json:"sla_deadline"`
	CreatedAt   time.Time `json:"created_at"`
	AISummary   string    `json:"ai_summary,omitempty"`
}

func buildFindingEmailBody(eventType string, payload FindingCreatedPayload) string {
	return strings.Join([]string{
		"HenKaiPan finding notification",
		"",
		"Event: " + eventType,
		"Finding ID: " + payload.FindingID,
		"Repository: " + payload.Repository,
		"Severity: " + strings.ToUpper(payload.Severity),
		"Scanner: " + payload.Scanner,
		"Rule ID: " + payload.RuleID,
		"Location: " + formatLocation(payload.FilePath, payload.Line),
		"Title: " + payload.Title,
	}, "\n")
}

func buildScanEmailBody(eventType string, payload ScanNotificationPayload) string {
	lines := []string{
		"HenKaiPan scan notification",
		"",
		"Event: " + eventType,
		"Scan ID: " + payload.ScanID,
		"Target: " + payload.Target,
		"Scanner: " + payload.Scanner,
		"Status: " + strings.ToUpper(payload.Status),
		fmt.Sprintf("Findings: %d", payload.FindingCount),
	}
	if strings.TrimSpace(payload.Error) != "" {
		lines = append(lines, "Error: "+payload.Error)
	}
	return strings.Join(lines, "\n")
}

func buildSLABreachEmailBody(payload SLABreachPayload) string {
	return strings.Join([]string{
		"HenKaiPan SLA breach notification",
		"",
		"Finding ID: " + payload.FindingID,
		"Scan ID: " + payload.ScanID,
		"Repository: " + payload.Repository,
		"Severity: " + strings.ToUpper(payload.Severity),
		"Scanner: " + payload.Scanner,
		"Rule ID: " + payload.RuleID,
		"Location: " + formatLocation(payload.FilePath, payload.Line),
		"SLA deadline: " + payload.SLADeadline.UTC().Format(time.RFC3339),
		"Title: " + payload.Title,
	}, "\n")
}

func scanEmailSubject(eventType string) string {
	if eventType == "scan.failed" {
		return "HenKaiPan scan failed"
	}
	return "HenKaiPan scan completed"
}

func formatLocation(path string, line int) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return "n/a"
	}
	if line > 0 {
		return fmt.Sprintf("%s:%d", path, line)
	}
	return path
}
