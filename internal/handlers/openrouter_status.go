package handlers

import (
	"log/slog"
	"net/http"

	"aspm/internal/ai"
)

// GetOpenRouterStatus exposes the current OpenRouter API key usage and limit.
// It requires the OpenRouter provider to be configured; otherwise it returns
// a 503 with a clear message so the UI can show the feature as unavailable.
func (h *Handler) GetOpenRouterStatus(w http.ResponseWriter, r *http.Request) {
	usage, err := ai.GetOpenRouterKeyUsage(r.Context())
	if err != nil {
		slog.WarnContext(r.Context(), "openrouter status unavailable", "error", err)
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"configured": false,
			"error":      "OpenRouter API key is not configured or unavailable",
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"configured": true,
		"usage":      usage,
	})
}
