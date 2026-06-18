package handlers

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	appmw "aspm/internal/middleware"
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

	slog.InfoContext(r.Context(), "login attempt", "username", req.Username)

	// Rate limiting: per-username (5 in 15min) + per-IP (10 in 15min)
	ip := clientIP(r)
	userKey := fmt.Sprintf("login:ratelimit:user:%s", req.Username)
	ipKey := fmt.Sprintf("login:ratelimit:ip:%s", ip)
	for _, k := range []struct {
		key string
		max int
	}{
		{userKey, 5},
		{ipKey, 10},
	} {
		pipe := appmw.Rdb.Pipeline()
		incr := pipe.Incr(r.Context(), k.key)
		pipe.Expire(r.Context(), k.key, 15*time.Minute)
		if _, err := pipe.Exec(r.Context()); err != nil {
			slog.ErrorContext(r.Context(), "login: rate limit check failed", "error", err)
			writeError(w, r, http.StatusTooManyRequests, "too many login attempts. try again later.")
			return
		}
		if int(incr.Val()) > k.max {
			slog.WarnContext(r.Context(), "login: rate limit exceeded", "key", k.key, "ip", ip)
			writeError(w, r, http.StatusTooManyRequests, "too many login attempts. try again later.")
			return
		}
	}

	creds, err := h.store.Users.GetCredentials(r.Context(), req.Username)
	if err != nil {
		slog.WarnContext(r.Context(), "login: user not found or db error", "username", req.Username, "error", err)
		h.writeUnauthorized(w, r)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(creds.PasswordHash), []byte(req.Password)); err != nil {
		slog.WarnContext(r.Context(), "login: password mismatch", "username", req.Username)
		h.writeUnauthorized(w, r)
		return
	}

	// Reset rate limit counters on successful login
	appmw.Rdb.Del(r.Context(), userKey, ipKey)

	h.store.Users.UpdateLastLogin(r.Context(), creds.ID)

	token, err := auth.IssueToken(req.Username, creds.Role, creds.ID, creds.TokenVersion)
	if err != nil {
		slog.ErrorContext(r.Context(), "login: token generation failed", "error", err)
		h.writeInternal(w, r, err, "token generation failed")
		return
	}
	slog.InfoContext(r.Context(), "login: token issued", "username", req.Username, "token_len", len(token))

	auth.SetAuthCookie(w, token, h.cookieSecure, h.cookieDomain, h.cookieSameSite)
	slog.InfoContext(r.Context(), "login: cookie set", "username", req.Username, "secure", h.cookieSecure, "domain", h.cookieDomain, "samesite", h.cookieSameSite)

	w.Header().Set("Cache-Control", "no-store")

	writeJSON(w, http.StatusOK, map[string]any{
		"role":     creds.Role,
		"username": req.Username,
	})
	slog.InfoContext(r.Context(), "login: success", "username", req.Username)
}

func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	auth.ClearAuthCookie(w, h.cookieSecure, h.cookieDomain, h.cookieSameSite)
	w.WriteHeader(http.StatusNoContent)
}

func clientIP(r *http.Request) string {
	return appmw.ClientIP(r)
}
