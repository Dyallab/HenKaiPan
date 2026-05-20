package handlers

import (
	"aspm/internal/license"
	"net/http"
)

func (h *Handler) GetConfigStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"ai": map[string]bool{
			"remediation": h.aiRemediation,
			"summary":     h.aiSummary,
			"validation":  h.aiValidation,
		},
		"features": map[string]bool{
			"risk_acceptance": h.license.HasFeature(license.FeatureRiskAcceptance),
		},
		"email_enabled":  h.emailEnabled,
		"frontend_url":   h.frontendURL != "",
		"webhook_secret": h.webhookSecret != "",
	})
}
