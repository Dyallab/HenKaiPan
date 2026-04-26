package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"aspm/internal/models"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type settingsRepo struct {
	db *pgxpool.Pool
}

func (r *settingsRepo) GetNotificationSettings(ctx context.Context) (*models.NotificationSettings, error) {
	var s models.NotificationSettings
	err := r.db.QueryRow(ctx, `
		SELECT alert_critical, alert_high, alert_scan_complete, alert_scan_failed, alert_sla_breach, updated_at
		FROM notification_settings
		WHERE singleton = TRUE`,
	).Scan(&s.AlertCritical, &s.AlertHigh, &s.AlertScanComplete, &s.AlertScanFailed, &s.AlertSLABreach, &s.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("get notification settings: %w", err)
	}
	return &s, nil
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

	var out models.NotificationSettings
	err = r.db.QueryRow(ctx, `
		UPDATE notification_settings
		SET alert_critical = $1,
		    alert_high = $2,
		    alert_scan_complete = $3,
		    alert_scan_failed = $4,
		    alert_sla_breach = $5,
		    updated_at = NOW()
		WHERE singleton = TRUE
		RETURNING alert_critical, alert_high, alert_scan_complete, alert_scan_failed, alert_sla_breach, updated_at`,
		current.AlertCritical, current.AlertHigh, current.AlertScanComplete, current.AlertScanFailed,
		current.AlertSLABreach,
	).Scan(&out.AlertCritical, &out.AlertHigh, &out.AlertScanComplete, &out.AlertScanFailed, &out.AlertSLABreach, &out.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("update notification settings: %w", err)
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
	j.HasToken = strings.TrimSpace(token) != ""
	j.TokenMasked = maskSecret(token)
	return &j, nil
}

func (r *settingsRepo) GetJiraCredentials(ctx context.Context) (*JiraCredentials, error) {
	var creds JiraCredentials
	var labelsRaw []byte
	err := r.db.QueryRow(ctx, `
		SELECT base_url, user_email, project_key, issue_type, labels, token, enabled
		FROM jira_integrations
		WHERE singleton = TRUE`,
	).Scan(&creds.BaseURL, &creds.UserEmail, &creds.ProjectKey, &creds.IssueType, &labelsRaw, &creds.Token, &creds.Enabled)
	if err != nil {
		return nil, fmt.Errorf("get jira credentials: %w", err)
	}
	_ = json.Unmarshal(labelsRaw, &creds.Labels)
	if creds.Labels == nil {
		creds.Labels = []string{}
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

	labelsJSON, err := json.Marshal(currentCreds.Labels)
	if err != nil {
		return nil, fmt.Errorf("marshal jira labels: %w", err)
	}

	_, err = r.db.Exec(ctx, `
		UPDATE jira_integrations
		SET base_url = $1,
		    user_email = $2,
		    project_key = $3,
		    issue_type = $4,
		    labels = $5,
		    enabled = $6,
		    token = $7,
		    updated_at = NOW()
		WHERE singleton = TRUE`,
		currentCreds.BaseURL,
		currentCreds.UserEmail,
		currentCreds.ProjectKey,
		currentCreds.IssueType,
		labelsJSON,
		currentCreds.Enabled,
		currentCreds.Token,
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
