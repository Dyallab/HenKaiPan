package handlers

import (
	"net/http"

	"aspm/internal/auth"
)

func (h *Handler) GetMe(w http.ResponseWriter, r *http.Request) {
	claims := auth.GetClaims(r)
	if claims == nil {
		writeError(w, r, http.StatusUnauthorized, "unauthorized")
		return
	}

	u, err := h.store.Users.GetByID(r.Context(), claims.UserID)
	if err != nil {
		writeError(w, r, http.StatusNotFound, "user not found")
		return
	}
	writeJSON(w, http.StatusOK, u)
}
