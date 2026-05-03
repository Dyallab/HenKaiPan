package handlers

import (
	"net/http"
)

func (h *Handler) GetLicense(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, h.license.Status())
}
