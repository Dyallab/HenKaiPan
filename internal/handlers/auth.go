package handlers

import (
	"encoding/json"
	"net/http"

	"aspm/internal/auth"

	"golang.org/x/crypto/bcrypt"
)

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Username == "" {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}

	id, hash, role, err := h.store.Users.GetCredentials(r.Context(), req.Username)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.Password)); err != nil {
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	h.store.Users.UpdateLastLogin(r.Context(), id)

	token, err := auth.IssueToken(req.Username, role, id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "token error")
		return
	}
	auth.SetAuthCookie(w, token, h.cookieSecure)

	w.Header().Set("Cache-Control", "no-store")

	writeJSON(w, http.StatusOK, map[string]any{
		"role":     role,
		"username": req.Username,
	})
}

func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	auth.ClearAuthCookie(w, h.cookieSecure)
	w.WriteHeader(http.StatusNoContent)
}
