package handlers

import (
	"encoding/json"
	"log/slog"
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
		slog.WarnContext(r.Context(), "login: decode error", "error", err)
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	slog.InfoContext(r.Context(), "login attempt", "username", req.Username)

	id, hash, role, err := h.store.Users.GetCredentials(r.Context(), req.Username)
	if err != nil {
		slog.WarnContext(r.Context(), "login: user not found or db error", "username", req.Username, "error", err)
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.Password)); err != nil {
		slog.WarnContext(r.Context(), "login: password mismatch", "username", req.Username)
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	h.store.Users.UpdateLastLogin(r.Context(), id)

	token, err := auth.IssueToken(req.Username, role, id)
	if err != nil {
		slog.ErrorContext(r.Context(), "login: token generation failed", "error", err)
		writeError(w, http.StatusInternalServerError, "token error")
		return
	}
	slog.InfoContext(r.Context(), "login: token issued", "username", req.Username, "token_len", len(token))

	auth.SetAuthCookie(w, token, h.cookieSecure)
	slog.InfoContext(r.Context(), "login: cookie set", "username", req.Username, "secure", h.cookieSecure)

	w.Header().Set("Cache-Control", "no-store")

	writeJSON(w, http.StatusOK, map[string]any{
		"role":     role,
		"username": req.Username,
	})
	slog.InfoContext(r.Context(), "login: success", "username", req.Username)
}

func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	auth.ClearAuthCookie(w, h.cookieSecure)
	w.WriteHeader(http.StatusNoContent)
}
