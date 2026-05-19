package handlers

import "net/http"

func (h *Handler) GetConfigStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"ai": map[string]bool{
			"remediation": h.aiRemediation,
			"summary":     h.aiSummary,
			"validation":  h.aiValidation,
		},
		"email_enabled":   h.emailEnabled,
		"frontend_url":    h.frontendURL != "",
		"webhook_secret":  h.webhookSecret != "",
	})
}
