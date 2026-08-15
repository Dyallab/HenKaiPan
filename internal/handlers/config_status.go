package handlers

import (
	"net/http"
)

// GetSSOStatus exposes only the SSO enablement flag for the public login page.
// The full config status endpoint is authenticated to avoid leaking deployment
// fingerprinting details to anonymous visitors.
func (h *Handler) GetSSOStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled": h.ssoEnabled,
	})
}

func (h *Handler) GetConfigStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"ai": map[string]bool{
			"remediation": h.aiRemediation,
			"summary":     h.aiSummary,
			"validation":  h.aiValidation,
		},
		"features": map[string]bool{
			"risk_acceptance": true,
			"sso":             h.ssoEnabled,
		},
		"email_enabled":  h.emailEnabled,
		"frontend_url":   h.frontendURL != "",
		"webhook_secret": h.webhookSecret != "",
	})
}
