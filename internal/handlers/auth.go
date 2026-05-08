package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"aspm/internal/auth"
	"aspm/internal/validation"

	"golang.org/x/crypto/bcrypt"
)

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	var req validation.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		slog.WarnContext(r.Context(), "login: decode error", "error", err)
		h.writeBadRequest(w, r, "invalid request")
		return
	}

	if validationErrs := validation.ValidateStruct(req); validationErrs != nil {
		h.writeValidationErrors(w, r, validationErrs)
		return
	}

	slog.InfoContext(r.Context(), "login attempt", "username", req.Email)

	id, hash, role, err := h.store.Users.GetCredentials(r.Context(), req.Email)
	if err != nil {
		slog.WarnContext(r.Context(), "login: user not found or db error", "username", req.Email, "error", err)
		h.writeUnauthorized(w, r)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.Password)); err != nil {
		slog.WarnContext(r.Context(), "login: password mismatch", "username", req.Email)
		h.writeUnauthorized(w, r)
		return
	}

	h.store.Users.UpdateLastLogin(r.Context(), id)

	token, err := auth.IssueToken(req.Email, role, id)
	if err != nil {
		slog.ErrorContext(r.Context(), "login: token generation failed", "error", err)
		h.writeInternal(w, r, err, "token generation failed")
		return
	}
	slog.InfoContext(r.Context(), "login: token issued", "username", req.Email, "token_len", len(token))

	auth.SetAuthCookie(w, token, h.cookieSecure, h.cookieDomain, h.cookieSameSite)
	slog.InfoContext(r.Context(), "login: cookie set", "username", req.Email, "secure", h.cookieSecure, "domain", h.cookieDomain, "samesite", h.cookieSameSite)

	w.Header().Set("Cache-Control", "no-store")

	writeJSON(w, http.StatusOK, map[string]any{
		"role":     role,
		"username": req.Email,
	})
	slog.InfoContext(r.Context(), "login: success", "username", req.Email)
}

func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	auth.ClearAuthCookie(w, h.cookieSecure, h.cookieDomain, h.cookieSameSite)
	w.WriteHeader(http.StatusNoContent)
}
