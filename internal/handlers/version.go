package handlers

import (
	"net/http"
	"runtime"
)

var (
	Version   = "dev"
	BuildDate = "unknown"
	Commit    = "unknown"
)

func (h *Handler) GetVersion(w http.ResponseWriter, r *http.Request) {
	response := map[string]string{
		"version":    Version,
		"build_date": BuildDate,
		"commit":     Commit,
		"go_version": runtime.Version(),
	}
	writeJSON(w, http.StatusOK, response)
}
