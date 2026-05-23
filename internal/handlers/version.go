package handlers

import (
	"net/http"
)

var (
	Version   = "dev"
	BuildDate = "unknown"
)

func (h *Handler) GetVersion(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"version":    Version,
		"build_date": BuildDate,
	})
}
