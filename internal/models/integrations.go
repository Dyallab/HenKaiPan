package models

import "time"

type NotificationSettings struct {
	AlertCritical     bool      `json:"alert_critical"`
	AlertHigh         bool      `json:"alert_high"`
	AlertScanComplete bool      `json:"alert_scan_complete"`
	AlertScanFailed   bool      `json:"alert_scan_failed"`
	AlertSLABreach    bool      `json:"alert_sla_breach"`
	EmailRecipients   []string  `json:"email_recipients"`
	UpdatedAt         time.Time `json:"updated_at"`
}

type JiraIntegration struct {
	BaseURL     string    `json:"base_url"`
	UserEmail   string    `json:"user_email"`
	ProjectKey  string    `json:"project_key"`
	IssueType   string    `json:"issue_type"`
	Labels      []string  `json:"labels"`
	Enabled     bool      `json:"enabled"`
	HasToken    bool      `json:"has_token"`
	TokenMasked string    `json:"token_masked,omitempty"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type JiraIssueLink struct {
	ID        string    `json:"id"`
	FindingID string    `json:"finding_id"`
	IssueKey  *string   `json:"issue_key,omitempty"`
	IssueURL  *string   `json:"issue_url,omitempty"`
	Status    *string   `json:"status,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}
