package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"aspm/internal/jira"
	"aspm/internal/models"
	"aspm/internal/repository"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
)

func (h *Handler) GetNotificationSettings(w http.ResponseWriter, r *http.Request) {
	settings, err := h.store.Settings.GetNotificationSettings(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to load notification settings")
		return
	}
	writeJSON(w, http.StatusOK, settings)
}

func (h *Handler) UpdateNotificationSettings(w http.ResponseWriter, r *http.Request) {
	var body struct {
		AlertCritical     *bool `json:"alert_critical"`
		AlertHigh         *bool `json:"alert_high"`
		AlertScanComplete *bool `json:"alert_scan_complete"`
		AlertScanFailed   *bool `json:"alert_scan_failed"`
		AlertSLABreach    *bool `json:"alert_sla_breach"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	settings, err := h.store.Settings.UpdateNotificationSettings(r.Context(), repository.NotificationSettingsUpdate{
		AlertCritical:     body.AlertCritical,
		AlertHigh:         body.AlertHigh,
		AlertScanComplete: body.AlertScanComplete,
		AlertScanFailed:   body.AlertScanFailed,
		AlertSLABreach:    body.AlertSLABreach,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to update notification settings")
		return
	}
	writeJSON(w, http.StatusOK, settings)
}

func (h *Handler) GetJiraIntegration(w http.ResponseWriter, r *http.Request) {
	integration, err := h.store.Settings.GetJiraIntegration(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to load jira integration")
		return
	}
	writeJSON(w, http.StatusOK, integration)
}

func (h *Handler) UpdateJiraIntegration(w http.ResponseWriter, r *http.Request) {
	var body struct {
		BaseURL    *string  `json:"base_url"`
		UserEmail  *string  `json:"user_email"`
		ProjectKey *string  `json:"project_key"`
		IssueType  *string  `json:"issue_type"`
		Labels     []string `json:"labels"`
		Enabled    *bool    `json:"enabled"`
		Token      *string  `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	if body.BaseURL != nil {
		trimmed := strings.TrimSpace(*body.BaseURL)
		if trimmed != "" {
			normalized, err := validateJiraCloudBaseURL(trimmed)
			if err != nil {
				writeError(w, http.StatusBadRequest, err.Error())
				return
			}
			trimmed = normalized
		}
		body.BaseURL = &trimmed
	}
	if body.UserEmail != nil {
		trimmed := strings.TrimSpace(*body.UserEmail)
		body.UserEmail = &trimmed
	}
	if body.ProjectKey != nil {
		trimmed := strings.TrimSpace(*body.ProjectKey)
		body.ProjectKey = &trimmed
	}
	if body.IssueType != nil {
		trimmed := strings.TrimSpace(*body.IssueType)
		body.IssueType = &trimmed
	}
	if body.Enabled != nil && *body.Enabled {
		if body.BaseURL != nil && *body.BaseURL == "" {
			writeError(w, http.StatusBadRequest, "jira base url required when enabling integration")
			return
		}
	}

	integration, err := h.store.Settings.UpsertJiraIntegration(r.Context(), repository.JiraIntegrationUpdate{
		BaseURL:    body.BaseURL,
		UserEmail:  body.UserEmail,
		ProjectKey: body.ProjectKey,
		IssueType:  body.IssueType,
		Labels:     body.Labels,
		Enabled:    body.Enabled,
		Token:      body.Token,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to update jira integration")
		return
	}
	writeJSON(w, http.StatusOK, integration)
}

func (h *Handler) GetFindingJiraIssue(w http.ResponseWriter, r *http.Request) {
	findingID := chi.URLParam(r, "id")
	link, err := h.store.Settings.GetJiraIssueLinkByFindingID(r.Context(), findingID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusNotFound, "jira ticket not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to load jira ticket")
		return
	}
	writeJSON(w, http.StatusOK, link)
}

func (h *Handler) CreateFindingJiraIssue(w http.ResponseWriter, r *http.Request) {
	findingID := chi.URLParam(r, "id")
	reserved, created, err := h.store.Settings.ReserveJiraIssueLink(r.Context(), findingID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to reserve jira ticket link")
		return
	}
	if !created {
		status := http.StatusOK
		if reserved.Status != nil && *reserved.Status == "pending" {
			status = http.StatusAccepted
		}
		writeJSON(w, status, reserved)
		return
	}

	finding, err := h.store.Findings.GetByID(r.Context(), findingID)
	if err != nil {
		_ = h.store.Settings.DeleteJiraIssueLink(r.Context(), findingID)
		writeError(w, http.StatusNotFound, "finding not found")
		return
	}
	creds, err := h.store.Settings.GetJiraCredentials(r.Context())
	if err != nil {
		_ = h.store.Settings.DeleteJiraIssueLink(r.Context(), findingID)
		writeError(w, http.StatusInternalServerError, "failed to load jira integration")
		return
	}
	if !creds.Enabled {
		_ = h.store.Settings.DeleteJiraIssueLink(r.Context(), findingID)
		writeError(w, http.StatusBadRequest, "jira integration is disabled")
		return
	}
	if strings.TrimSpace(creds.BaseURL) == "" || strings.TrimSpace(creds.UserEmail) == "" || strings.TrimSpace(creds.Token) == "" || strings.TrimSpace(creds.ProjectKey) == "" || strings.TrimSpace(creds.IssueType) == "" {
		_ = h.store.Settings.DeleteJiraIssueLink(r.Context(), findingID)
		writeError(w, http.StatusBadRequest, "jira integration is incomplete")
		return
	}
	validatedBaseURL, err := validateJiraCloudBaseURL(creds.BaseURL)
	if err != nil {
		_ = h.store.Settings.DeleteJiraIssueLink(r.Context(), findingID)
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	client := jira.NewClient(validatedBaseURL, creds.UserEmail, creds.Token)
	summary := fmt.Sprintf("[%s] %s", strings.ToUpper(finding.Severity), finding.Title)
	description := buildJiraFindingDescription(finding, buildHenKaiPanFindingURL(h.frontendURL, finding.ID))
	resp, err := client.CreateIssue(r.Context(), jira.CreateIssueRequest{
		ProjectKey:  creds.ProjectKey,
		IssueType:   creds.IssueType,
		Summary:     summary,
		Description: description,
		Labels:      append([]string{"henkaipan", "security-finding"}, creds.Labels...),
	})
	if err != nil {
		_ = h.store.Settings.DeleteJiraIssueLink(r.Context(), findingID)
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}

	status := "created"
	issueKey := resp.Key
	issueURL := strings.TrimRight(validatedBaseURL, "/") + "/browse/" + resp.Key
	link, err := h.store.Settings.UpsertJiraIssueLink(r.Context(), repository.JiraIssueLinkUpsert{
		FindingID: finding.ID,
		IssueKey:  &issueKey,
		IssueURL:  &issueURL,
		Status:    &status,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "jira ticket created but failed to persist link")
		return
	}
	writeJSON(w, http.StatusCreated, link)
}
func buildJiraFindingDescription(finding *models.Finding, henKaiPanURL string) string {
	var parts []string
	parts = append(parts,
		"HenKaiPan finding details",
	)
	if henKaiPanURL != "" {
		parts = append(parts, henKaiPanURL)
	} else {
		parts = append(parts, "Finding URL unavailable. Configure FRONTEND_BASE_URL to enable backlinks.")
	}

	parts = append(parts,
		"",
		"Overview",
		"Finding ID: "+finding.ID,
		"Scan ID: "+finding.ScanID,
		"Severity: "+string(finding.Severity),
		"Scanner: "+finding.Scanner,
		"Rule ID: "+finding.RuleID,
		"Status: "+string(finding.Status),
		"Created at: "+finding.CreatedAt.UTC().Format(time.RFC3339),
	)
	if finding.AssignedTo != nil && strings.TrimSpace(*finding.AssignedTo) != "" {
		parts = append(parts, "Assigned to: "+strings.TrimSpace(*finding.AssignedTo))
	}
	parts = append(parts,
		fmt.Sprintf("False positive: %t", finding.FalsePositive),
		fmt.Sprintf("Suppressed: %t", finding.Suppressed),
	)
	if finding.SLADeadline != nil {
		parts = append(parts, "SLA deadline: "+finding.SLADeadline.UTC().Format(time.RFC3339))
	}
	if finding.ConfidenceScore != nil {
		parts = append(parts, fmt.Sprintf("Confidence score: %.2f", *finding.ConfidenceScore))
	}
	if finding.CorroborationCount > 0 {
		parts = append(parts, fmt.Sprintf("Corroboration count: %d", finding.CorroborationCount))
	}

	if finding.FilePath != "" {
		location := finding.FilePath
		if finding.LineStart > 0 {
			location = fmt.Sprintf("%s:%d", finding.FilePath, finding.LineStart)
			if finding.LineEnd > finding.LineStart {
				location = fmt.Sprintf("%s-%d", location, finding.LineEnd)
			}
		}
		parts = append(parts, "", "Location", location)
	}
	if finding.CVEID != nil && strings.TrimSpace(*finding.CVEID) != "" {
		parts = append(parts, "CVE: "+*finding.CVEID)
	}
	if finding.CWEID != nil && strings.TrimSpace(*finding.CWEID) != "" {
		parts = append(parts, "CWE: "+*finding.CWEID)
	}
	parts = append(parts, "", "Title: "+finding.Title)
	return strings.Join(parts, "\n")
}

func buildHenKaiPanFindingURL(frontendBaseURL, findingID string) string {
	frontendBaseURL = strings.TrimSpace(frontendBaseURL)
	if frontendBaseURL == "" || strings.TrimSpace(findingID) == "" {
		return ""
	}

	parsed, err := url.Parse(frontendBaseURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return ""
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return ""
	}
	if parsed.User != nil {
		return ""
	}

	basePath := strings.TrimRight(parsed.Path, "/")
	parsed.Path = basePath + "/dashboard/findings/detail"
	parsed.RawPath = ""
	query := parsed.Query()
	query.Set("id", findingID)
	parsed.RawQuery = query.Encode()
	parsed.Fragment = ""
	return parsed.String()
}

func validateJiraCloudBaseURL(raw string) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid jira base url")
	}
	if parsed.Scheme != "https" {
		return "", fmt.Errorf("jira base url must use https")
	}
	host := strings.ToLower(parsed.Hostname())
	if host == "" || !strings.HasSuffix(host, ".atlassian.net") {
		return "", fmt.Errorf("jira base url must be a Jira Cloud *.atlassian.net URL")
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return "", fmt.Errorf("jira base url must not include a path")
	}
	return "https://" + host, nil
}
