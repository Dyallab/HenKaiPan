package tasks

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"aspm/internal/ai"
	"aspm/internal/config"
	"aspm/internal/repository"
	"aspm/internal/scanner"

	"github.com/hibiken/asynq"
)

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
			To:       cfg.EmailTo,
			Enabled:  cfg.EmailEnabled,
		},
	}
}

type runResult struct {
	stdout []byte
	log    string
	err    error
}

// HandleScan is the single asynq handler for all scanners.
func HandleScan(scans repository.ScanRepository, findings repository.FindingRepository, policies repository.PolicyRepository, webhooks repository.WebhookRepository, settings repository.SettingsRepository, queue *asynq.Client, notifications NotificationConfig) asynq.HandlerFunc {
	return func(ctx context.Context, t *asynq.Task) error {
		p, err := UnmarshalPayload(t.Payload())
		if err != nil {
			return err
		}

		log := slog.With("scan_id", p.ScanID, "scanner", p.Scanner, "target", p.Target)

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
			dir, cloneLog, err := cloneRepo(ctx, p.Target, p.ScanID)
			if err != nil {
				scans.MarkFailed(ctx, p.ScanID, err.Error(), cloneLog)
				enqueueScanNotification(ctx, scans, settings, webhooks, queue, notifications, p.ScanID, "scan.failed", err.Error(), time.Now())
				log.Error("clone failed", "err", err)
				return err
			}
			defer os.RemoveAll(dir)
			result = runDocker(sc, dir)

		case scanner.TargetURL:
			result = runDockerURL(sc, p.Target)
		}

		if result.err != nil && len(result.stdout) == 0 {
			scans.MarkFailed(ctx, p.ScanID, result.err.Error(), result.log)
			enqueueScanNotification(ctx, scans, settings, webhooks, queue, notifications, p.ScanID, "scan.failed", result.err.Error(), time.Now())
			log.Error("docker run failed", "err", result.err)
			return fmt.Errorf("%s docker run: %w", sc.Name, result.err)
		}

		parsed, parseErr := sc.Parse(result.stdout)
		if parseErr != nil {
			log.Warn("parse warning", "err", parseErr)
		}

		now := time.Now()
		inserted := 0
		summary := newScanFindingSummary(p.Target)
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

			findingID, err := findings.Insert(ctx, repository.FindingInsert{
				ScanID: p.ScanID, Scanner: sc.Name, RuleID: f.RuleID,
				Title: f.Title, Description: f.Description,
				Severity: norm, FilePath: f.FilePath,
				LineStart: f.LineStart, LineEnd: f.LineEnd,
				CodeSnippet: f.CodeSnippet, Raw: f.Raw,
				SLADeadline: sla, CVEID: cveID, CWEID: cweID,
				Suppressed: suppressed,
			})
			if err != nil {
				log.Error("insert finding failed", "rule_id", f.RuleID, "err", err)
				continue
			}
			inserted++
			if err := findings.RefreshBatchCorrelation(ctx, findingID); err != nil {
				log.Warn("refresh batch correlation failed", "finding_id", findingID, "err", err)
			}
			if strings.TrimSpace(f.Description) == "" {
				enqueueFindingSummary(ctx, findings, queue, findingID)
			}
			if !suppressed {
				summary.Add(norm, f.Title, f.RuleID, f.FilePath, f.LineStart, sc.Name)
				applyPolicies(ctx, policies, findingID, sc.Name, norm, f.RuleID, f.FilePath)
				enqueueAgentValidate(ctx, queue, findingID)
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

func cloneRepo(ctx context.Context, url, scanID string) (dir string, execLog string, err error) {
	dir = filepath.Join(os.TempDir(), "aspm-scan-"+scanID)
	start := time.Now()
	cmd := exec.CommandContext(ctx, "git", "clone", "--depth=50", url, dir)
	out, cloneErr := cmd.CombinedOutput()
	execLog = buildSimpleLog("git clone --depth=50 "+url, out, nil, cloneErr, time.Since(start))
	if cloneErr != nil {
		return "", execLog, fmt.Errorf("git clone: %w\n%s", cloneErr, out)
	}
	return dir, execLog, nil
}

func buildDockerCmd(sc scanner.Scanner, args []string) *exec.Cmd {
	base := []string{"run", "--rm"}
	for k, v := range sc.Env {
		base = append(base, "-e", k+"="+v)
	}
	for _, vol := range sc.ExtraVolumes {
		base = append(base, "-v", vol)
	}
	if len(sc.Entrypoint) > 0 {
		base = append(base, "--entrypoint", sc.Entrypoint[0])
	}
	base = append(base, args...)
	return exec.Command("docker", base...)
}

func runDocker(sc scanner.Scanner, mountSrc string) runResult {
	args := []string{}
	if sc.MountDst != "" {
		args = append(args, "-v", fmt.Sprintf("%s:%s", mountSrc, sc.MountDst))
	}
	if sc.WorkDir != "" {
		args = append(args, "-w", sc.WorkDir)
	}
	args = append(args, sc.Image)
	args = append(args, sc.BuildArgs(sc.MountDst)...)
	return execute(sc, args)
}

func runDockerURL(sc scanner.Scanner, target string) runResult {
	args := []string{sc.Image}
	args = append(args, sc.BuildArgs(target)...)
	return execute(sc, args)
}

func execute(sc scanner.Scanner, dockerArgs []string) runResult {
	cmd := buildDockerCmd(sc, dockerArgs)
	cmdStr := "docker " + strings.Join(cmd.Args[1:], " ")

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	start := time.Now()
	runErr := cmd.Run()

	return runResult{
		stdout: stdout.Bytes(),
		log:    buildSimpleLog(cmdStr, stdout.Bytes(), stderr.Bytes(), runErr, time.Since(start)),
		err:    runErr,
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
	payload, err := MarshalAgentValidatePayload(AgentValidatePayload{FindingID: findingID})
	if err != nil {
		slog.Warn("marshal agent:validate payload failed", "finding_id", findingID, "err", err)
		return
	}
	if _, err := queue.EnqueueContext(ctx, asynq.NewTask(TypeAgentValidate, payload)); err != nil {
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
	payload, err := MarshalAgentSummarizePayload(AgentSummarizePayload{FindingID: findingID})
	if err != nil {
		slog.Warn("marshal agent:summarize payload failed", "finding_id", findingID, "err", err)
		return
	}
	if _, err := queue.EnqueueContext(ctx, asynq.NewTask(TypeAgentSummarize, payload)); err != nil {
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
	switch payload.Severity {
	case "critical":
		if notificationSettings.AlertCritical {
			enqueueWebhookEvent(ctx, webhooks, queue, "finding.critical", payload)
			enqueueEmailEvent(ctx, queue, notifications.Email, "Critical finding detected", buildFindingEmailBody("finding.critical", payload))
		}
	case "high":
		if notificationSettings.AlertHigh {
			enqueueWebhookEvent(ctx, webhooks, queue, "finding.high", payload)
			enqueueEmailEvent(ctx, queue, notifications.Email, "High severity finding detected", buildFindingEmailBody("finding.high", payload))
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
	enqueueWebhookEvent(ctx, webhooks, queue, eventType, payload)
	enqueueEmailEvent(ctx, queue, notifications.Email, scanEmailSubject(eventType), buildScanEmailBody(eventType, payload))
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

func enqueueEmailEvent(ctx context.Context, queue *asynq.Client, cfg EmailConfig, subject, body string) bool {
	if !cfg.Enabled {
		return false
	}
	payload, err := MarshalEmailSendPayload(EmailSendPayload{Subject: subject, Body: body})
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

type scanFindingSummary struct {
	Repository string
	Total      int
	Counts     map[string]int
	Items      []findingSummaryItem
}

type findingSummaryItem struct {
	Severity string
	Title    string
	RuleID   string
	FilePath string
	Line     int
	Scanner  string
}

func newScanFindingSummary(repository string) *scanFindingSummary {
	return &scanFindingSummary{Repository: repository, Counts: map[string]int{}}
}

func (s *scanFindingSummary) Add(severity, title, ruleID, filePath string, line int, scanner string) {
	s.Total++
	s.Counts[severity]++
	if len(s.Items) >= 10 {
		return
	}
	s.Items = append(s.Items, findingSummaryItem{Severity: severity, Title: title, RuleID: ruleID, FilePath: filePath, Line: line, Scanner: scanner})
}

func buildGitHubPRSummaryBody(scanID string, summary *scanFindingSummary) string {
	var b strings.Builder
	b.WriteString("## HenKaiPan security scan summary\n\n")
	fmt.Fprintf(&b, "Scan `%s` found **%d** finding(s) in `%s`.\n\n", scanID, summary.Total, summary.Repository)
	b.WriteString("| Severity | Count |\n|---|---:|\n")
	for _, severity := range []string{"critical", "high", "medium", "low", "info"} {
		if count := summary.Counts[severity]; count > 0 {
			fmt.Fprintf(&b, "| %s | %d |\n", strings.ToUpper(severity), count)
		}
	}
	if len(summary.Items) > 0 {
		b.WriteString("\n### Top findings\n")
		for _, item := range summary.Items {
			location := item.FilePath
			if item.Line > 0 {
				location = fmt.Sprintf("%s:%d", item.FilePath, item.Line)
			}
			fmt.Fprintf(&b, "- **%s** `%s` — %s", strings.ToUpper(item.Severity), item.Scanner, item.Title)
			if item.RuleID != "" {
				fmt.Fprintf(&b, " (`%s`)", item.RuleID)
			}
			if strings.TrimSpace(location) != "" {
				fmt.Fprintf(&b, " at `%s`", location)
			}
			b.WriteString("\n")
		}
	}
	b.WriteString("\n_Comment generated by HenKaiPan ASPM._")
	return b.String()
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
		emailQueued := enqueueEmailEvent(ctx, queue, notifications.Email, "SLA breach detected", buildSLABreachEmailBody(payload))
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
