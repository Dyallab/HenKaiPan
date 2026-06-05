package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"aspm/internal/models"
	"aspm/internal/secrets"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type settingsRepo struct {
	db *pgxpool.Pool
}

func (r *settingsRepo) GetNotificationSettings(ctx context.Context) (*models.NotificationSettings, error) {
	var s models.NotificationSettings
	var emailRecipientsRaw []byte
	err := r.db.QueryRow(ctx, `
		SELECT alert_critical, alert_high, alert_scan_complete, alert_scan_failed, alert_sla_breach, email_recipients, digest_frequency, digest_time, updated_at
		FROM notification_settings
		WHERE singleton = TRUE`,
	).Scan(&s.AlertCritical, &s.AlertHigh, &s.AlertScanComplete, &s.AlertScanFailed, &s.AlertSLABreach, &emailRecipientsRaw, &s.DigestFrequency, &s.DigestTime, &s.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return r.initDefaultNotificationSettings(ctx)
		}
		return nil, fmt.Errorf("get notification settings: %w", err)
	}
	_ = json.Unmarshal(emailRecipientsRaw, &s.EmailRecipients)
	if s.EmailRecipients == nil {
		s.EmailRecipients = []string{}
	}
	return &s, nil
}

func (r *settingsRepo) initDefaultNotificationSettings(ctx context.Context) (*models.NotificationSettings, error) {
	emailRecipientsJSON, _ := json.Marshal([]string{})
	var out models.NotificationSettings
	var emailRecipientsRaw []byte
	err := r.db.QueryRow(ctx, `
		INSERT INTO notification_settings (singleton, alert_critical, alert_high, alert_scan_complete, alert_scan_failed, alert_sla_breach, email_recipients, digest_frequency, digest_time)
		VALUES (TRUE, TRUE, TRUE, FALSE, FALSE, FALSE, $1, 'weekly', '09:00')
		ON CONFLICT (singleton) DO NOTHING
		RETURNING alert_critical, alert_high, alert_scan_complete, alert_scan_failed, alert_sla_breach, email_recipients, digest_frequency, digest_time, updated_at`,
		emailRecipientsJSON,
	).Scan(&out.AlertCritical, &out.AlertHigh, &out.AlertScanComplete, &out.AlertScanFailed, &out.AlertSLABreach, &emailRecipientsRaw, &out.DigestFrequency, &out.DigestTime, &out.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return r.GetNotificationSettings(ctx)
		}
		return nil, fmt.Errorf("init notification settings: %w", err)
	}
	_ = json.Unmarshal(emailRecipientsRaw, &out.EmailRecipients)
	if out.EmailRecipients == nil {
		out.EmailRecipients = []string{}
	}
	return &out, nil
}

func (r *settingsRepo) UpdateNotificationSettings(ctx context.Context, upd NotificationSettingsUpdate) (*models.NotificationSettings, error) {
	current, err := r.GetNotificationSettings(ctx)
	if err != nil {
		return nil, err
	}
	if upd.AlertCritical != nil {
		current.AlertCritical = *upd.AlertCritical
	}
	if upd.AlertHigh != nil {
		current.AlertHigh = *upd.AlertHigh
	}
	if upd.AlertScanComplete != nil {
		current.AlertScanComplete = *upd.AlertScanComplete
	}
	if upd.AlertScanFailed != nil {
		current.AlertScanFailed = *upd.AlertScanFailed
	}
	if upd.AlertSLABreach != nil {
		current.AlertSLABreach = *upd.AlertSLABreach
	}
	if upd.EmailRecipients != nil {
		current.EmailRecipients = compactStrings(*upd.EmailRecipients)
	}
	if upd.DigestFrequency != nil {
		current.DigestFrequency = *upd.DigestFrequency
	}
	if upd.DigestTime != nil {
		current.DigestTime = *upd.DigestTime
	}

	emailRecipientsJSON, err := json.Marshal(current.EmailRecipients)
	if err != nil {
		return nil, fmt.Errorf("marshal email recipients: %w", err)
	}
	var emailRecipientsRaw []byte

	var out models.NotificationSettings
	err = r.db.QueryRow(ctx, `
		UPDATE notification_settings
		SET alert_critical = @alert_critical,
		    alert_high = @alert_high,
		    alert_scan_complete = @alert_scan_complete,
		    alert_scan_failed = @alert_scan_failed,
		    alert_sla_breach = @alert_sla_breach,
		    email_recipients = @email_recipients,
		    digest_frequency = @digest_frequency,
		    digest_time = @digest_time,
		    updated_at = NOW()
		WHERE singleton = TRUE
		RETURNING alert_critical, alert_high, alert_scan_complete, alert_scan_failed, alert_sla_breach, email_recipients, digest_frequency, digest_time, updated_at`,
		pgx.NamedArgs{
			"alert_critical":      current.AlertCritical,
			"alert_high":          current.AlertHigh,
			"alert_scan_complete": current.AlertScanComplete,
			"alert_scan_failed":   current.AlertScanFailed,
			"alert_sla_breach":    current.AlertSLABreach,
			"email_recipients":    emailRecipientsJSON,
			"digest_frequency":    current.DigestFrequency,
			"digest_time":         current.DigestTime,
		},
	).Scan(&out.AlertCritical, &out.AlertHigh, &out.AlertScanComplete, &out.AlertScanFailed, &out.AlertSLABreach, &emailRecipientsRaw, &out.DigestFrequency, &out.DigestTime, &out.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("update notification settings: %w", err)
	}
	_ = json.Unmarshal(emailRecipientsRaw, &out.EmailRecipients)
	if out.EmailRecipients == nil {
		out.EmailRecipients = []string{}
	}
	return &out, nil
}

func (r *settingsRepo) GetJiraIntegration(ctx context.Context) (*models.JiraIntegration, error) {
	var j models.JiraIntegration
	var labelsRaw []byte
	var token string
	err := r.db.QueryRow(ctx, `
		SELECT base_url, user_email, project_key, issue_type, labels, enabled, token, updated_at
		FROM jira_integrations
		WHERE singleton = TRUE`,
	).Scan(&j.BaseURL, &j.UserEmail, &j.ProjectKey, &j.IssueType, &labelsRaw, &j.Enabled, &token, &j.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("get jira integration: %w", err)
	}
	_ = json.Unmarshal(labelsRaw, &j.Labels)
	if j.Labels == nil {
		j.Labels = []string{}
	}
	decrypted, err := secrets.Decrypt(token)
	if err != nil {
		return nil, fmt.Errorf("decrypt jira token: %w", err)
	}
	j.HasToken = strings.TrimSpace(decrypted) != ""
	j.TokenMasked = maskSecret(decrypted)
	return &j, nil
}

func (r *settingsRepo) GetJiraCredentials(ctx context.Context) (*JiraCredentials, error) {
	var creds JiraCredentials
	var labelsRaw []byte
	var token string
	err := r.db.QueryRow(ctx, `
		SELECT base_url, user_email, project_key, issue_type, labels, token, enabled
		FROM jira_integrations
		WHERE singleton = TRUE`,
	).Scan(&creds.BaseURL, &creds.UserEmail, &creds.ProjectKey, &creds.IssueType, &labelsRaw, &token, &creds.Enabled)
	if err != nil {
		return nil, fmt.Errorf("get jira credentials: %w", err)
	}
	_ = json.Unmarshal(labelsRaw, &creds.Labels)
	if creds.Labels == nil {
		creds.Labels = []string{}
	}
	creds.Token, err = secrets.Decrypt(token)
	if err != nil {
		return nil, fmt.Errorf("decrypt jira credentials: %w", err)
	}
	return &creds, nil
}

func (r *settingsRepo) UpsertJiraIntegration(ctx context.Context, upd JiraIntegrationUpdate) (*models.JiraIntegration, error) {
	currentCreds, err := r.GetJiraCredentials(ctx)
	if err != nil {
		return nil, err
	}

	if upd.BaseURL != nil {
		currentCreds.BaseURL = strings.TrimSpace(*upd.BaseURL)
	}
	if upd.UserEmail != nil {
		currentCreds.UserEmail = strings.TrimSpace(*upd.UserEmail)
	}
	if upd.ProjectKey != nil {
		currentCreds.ProjectKey = strings.TrimSpace(*upd.ProjectKey)
	}
	if upd.IssueType != nil {
		currentCreds.IssueType = strings.TrimSpace(*upd.IssueType)
	}
	if upd.Labels != nil {
		currentCreds.Labels = compactStrings(upd.Labels)
	}
	if upd.Enabled != nil {
		currentCreds.Enabled = *upd.Enabled
	}
	if upd.Token != nil {
		currentCreds.Token = strings.TrimSpace(*upd.Token)
	}

	encryptedToken, err := secrets.Encrypt(currentCreds.Token)
	if err != nil {
		return nil, fmt.Errorf("encrypt jira token: %w", err)
	}

	labelsJSON, err := json.Marshal(currentCreds.Labels)
	if err != nil {
		return nil, fmt.Errorf("marshal jira labels: %w", err)
	}

	_, err = r.db.Exec(ctx, `
		UPDATE jira_integrations
		SET base_url = @base_url,
		    user_email = @user_email,
		    project_key = @project_key,
		    issue_type = @issue_type,
		    labels = @labels,
		    enabled = @enabled,
		    token = @token,
		    updated_at = NOW()
		WHERE singleton = TRUE`,
		pgx.NamedArgs{
			"base_url":     currentCreds.BaseURL,
			"user_email":   currentCreds.UserEmail,
			"project_key":  currentCreds.ProjectKey,
			"issue_type":   currentCreds.IssueType,
			"labels":       labelsJSON,
			"enabled":      currentCreds.Enabled,
			"token":        encryptedToken,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("update jira integration: %w", err)
	}

	return r.GetJiraIntegration(ctx)
}

func (r *settingsRepo) GetJiraIssueLinkByFindingID(ctx context.Context, findingID string) (*models.JiraIssueLink, error) {
	var out models.JiraIssueLink
	err := r.db.QueryRow(ctx, `
		SELECT id, finding_id, issue_key, issue_url, status, created_at
		FROM jira_issue_links
		WHERE finding_id = $1`, findingID,
	).Scan(&out.ID, &out.FindingID, &out.IssueKey, &out.IssueURL, &out.Status, &out.CreatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, err
		}
		return nil, fmt.Errorf("get jira issue link: %w", err)
	}
	return &out, nil
}

func (r *settingsRepo) ReserveJiraIssueLink(ctx context.Context, findingID string) (*models.JiraIssueLink, bool, error) {
	status := "pending"
	var out models.JiraIssueLink
	err := r.db.QueryRow(ctx, `
		INSERT INTO jira_issue_links (finding_id, status)
		VALUES ($1, $2)
		ON CONFLICT (finding_id) DO NOTHING
		RETURNING id, finding_id, issue_key, issue_url, status, created_at`,
		findingID, status,
	).Scan(&out.ID, &out.FindingID, &out.IssueKey, &out.IssueURL, &out.Status, &out.CreatedAt)
	if err == nil {
		return &out, true, nil
	}
	if err != pgx.ErrNoRows {
		return nil, false, fmt.Errorf("reserve jira issue link: %w", err)
	}

	existing, err := r.GetJiraIssueLinkByFindingID(ctx, findingID)
	if err != nil {
		return nil, false, err
	}
	return existing, false, nil
}

func (r *settingsRepo) UpsertJiraIssueLink(ctx context.Context, link JiraIssueLinkUpsert) (*models.JiraIssueLink, error) {
	var out models.JiraIssueLink
	err := r.db.QueryRow(ctx, `
		INSERT INTO jira_issue_links (finding_id, issue_key, issue_url, status)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (finding_id) DO UPDATE
		SET issue_key = EXCLUDED.issue_key,
		    issue_url = EXCLUDED.issue_url,
		    status = EXCLUDED.status
		RETURNING id, finding_id, issue_key, issue_url, status, created_at`,
		link.FindingID, link.IssueKey, link.IssueURL, link.Status,
	).Scan(&out.ID, &out.FindingID, &out.IssueKey, &out.IssueURL, &out.Status, &out.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("upsert jira issue link: %w", err)
	}
	return &out, nil
}

func (r *settingsRepo) DeleteJiraIssueLink(ctx context.Context, findingID string) error {
	_, err := r.db.Exec(ctx, `DELETE FROM jira_issue_links WHERE finding_id = $1`, findingID)
	if err != nil {
		return fmt.Errorf("delete jira issue link: %w", err)
	}
	return nil
}

func compactStrings(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		out = append(out, trimmed)
	}
	if out == nil {
		return []string{}
	}
	return out
}

func maskSecret(secret string) string {
	secret = strings.TrimSpace(secret)
	if secret == "" {
		return ""
	}
	if len(secret) <= 4 {
		return strings.Repeat("•", len(secret))
	}
	return strings.Repeat("•", len(secret)-4) + secret[len(secret)-4:]
}
