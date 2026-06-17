package handlers

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"aspm/internal/auth"
	"aspm/internal/repository"
	"aspm/internal/tasks"
	"aspm/internal/validation"

	"github.com/go-chi/chi/v5"
	"github.com/hibiken/asynq"
	"golang.org/x/crypto/bcrypt"
)

func (h *Handler) ListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := h.store.Users.List(r.Context())
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "failed to list users")
		return
	}
	writeJSON(w, http.StatusOK, users)
}

func (h *Handler) CreateUser(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Username == "" || body.Email == "" || body.Password == "" {
		writeError(w, r, http.StatusBadRequest, "username, email, and password required")
		return
	}
	if body.Role == "" {
		body.Role = "viewer"
	}
	if !validation.IsValid(validation.Roles, body.Role) {
		writeError(w, r, http.StatusBadRequest, "role must be admin or viewer")
		return
	}

	if err := h.checkUserLimit(r.Context()); err != nil {
		h.writeLimitError(w, r, err)
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(body.Password), bcrypt.DefaultCost)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "password hash error")
		return
	}

	u, err := h.store.Users.Create(r.Context(), repository.UserCreate{
		Username: body.Username, Email: body.Email,
		PasswordHash: string(hash), Role: body.Role,
	})
	if err != nil {
		writeError(w, r, http.StatusConflict, "username or email already exists")
		return
	}

	h.auditLog(r, "user.create", "user", u.ID, nil, u)

	writeJSON(w, http.StatusCreated, u)
}

func (h *Handler) UpdateUser(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	var body struct {
		Email           *string `json:"email"`
		Role            *string `json:"role"`
		Password        *string `json:"password"`
		CurrentPassword *string `json:"current_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid body")
		return
	}

	if body.Role != nil {
		if !validation.IsValid(validation.Roles, *body.Role) {
			writeError(w, r, http.StatusBadRequest, "role must be admin or viewer")
			return
		}
	}

	passwordChanging := body.Password != nil && *body.Password != ""
	roleChanging := body.Role != nil
	emailChanging := body.Email != nil && *body.Email != ""

	// For sensitive changes (password, role, or email), require current_password verification
	if passwordChanging || roleChanging || emailChanging {
		claims := auth.GetClaims(r)
		if claims == nil {
			h.writeUnauthorized(w, r)
			return
		}

		hash, err := h.store.Users.GetPasswordHashByID(r.Context(), claims.UserID)
		if err != nil {
			slog.ErrorContext(r.Context(), "failed to get requesting user's password hash", "err", err)
			h.writeInternal(w, r, err, "failed to verify credentials")
			return
		}

		if body.CurrentPassword == nil || *body.CurrentPassword == "" {
			writeError(w, r, http.StatusBadRequest, "current_password is required for sensitive changes")
			return
		}

		if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(*body.CurrentPassword)); err != nil {
			h.writeForbidden(w, r)
			return
		}
	}

	var hashPtr *string
	if passwordChanging {
		h, err := bcrypt.GenerateFromPassword([]byte(*body.Password), bcrypt.DefaultCost)
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "password hash error")
			return
		}
		s := string(h)
		hashPtr = &s
	}

	oldUser, _ := h.store.Users.GetByID(r.Context(), id)

	u, err := h.store.Users.Update(r.Context(), id, repository.UserUpdate{
		Email: body.Email, Role: body.Role, PasswordHash: hashPtr,
	})
	if err != nil {
		writeError(w, r, http.StatusNotFound, "user not found")
		return
	}

	// Bump token_version on sensitive changes to invalidate existing sessions
	if passwordChanging || roleChanging || emailChanging {
		if err := h.store.Users.BumpTokenVersion(r.Context(), id); err != nil {
			slog.ErrorContext(r.Context(), "failed to bump token version", "user_id", id, "err", err)
		}
	}

	h.auditLog(r, "user.update", "user", u.ID, oldUser, u)

	if emailChanging && oldUser != nil && *body.Email != oldUser.Email {
		h.notifySecurityEvent(r.Context(), u, "email_changed",
			"Your email address has been changed",
			fmt.Sprintf("Your email address has been changed from '%s' to '%s'. If you did not request this change, contact your administrator immediately.", oldUser.Email, *body.Email))

		if h.emailEnabled && oldUser.Email != "" {
			payload, err := tasks.MarshalEmailSendPayload(tasks.EmailSendPayload{
				Subject: "[HenKaiPan] Your email address was changed",
				Body:    fmt.Sprintf("Your email address on HenKaiPan has been changed from '%s' to '%s'. If you did not request this change, contact your administrator immediately.", oldUser.Email, *body.Email),
				To:      []string{oldUser.Email},
			})
			if err != nil {
				slog.ErrorContext(r.Context(), "marshal email change notification failed", "err", err)
			} else if _, err := h.queue.EnqueueContext(r.Context(),
				asynq.NewTask(tasks.TypeEmailSend, payload),
				asynq.MaxRetry(5),
				asynq.Timeout(30*time.Second),
			); err != nil {
				slog.ErrorContext(r.Context(), "enqueue email change notification failed", "err", err)
			}
		}
	}

	if roleChanging && oldUser != nil && *body.Role != oldUser.Role {
		h.notifySecurityEvent(r.Context(), u, "role_changed",
			"Your role has been changed",
			fmt.Sprintf("Your role has been changed from '%s' to '%s'.", oldUser.Role, *body.Role))
	}

	writeJSON(w, http.StatusOK, u)
}

func (h *Handler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	var body struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Password == "" {
		writeError(w, r, http.StatusBadRequest, "password is required")
		return
	}

	claims := auth.GetClaims(r)
	if claims == nil {
		h.writeUnauthorized(w, r)
		return
	}

	oldUser, err := h.store.Users.GetByID(r.Context(), id)
	if err != nil {
		h.writeNotFound(w, r, "user")
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(body.Password), bcrypt.DefaultCost)
	if err != nil {
		h.writeInternal(w, r, err, "password hash error")
		return
	}
	s := string(hash)

	u, err := h.store.Users.Update(r.Context(), id, repository.UserUpdate{PasswordHash: &s})
	if err != nil {
		h.writeInternal(w, r, err, "failed to reset password")
		return
	}

	// Invalidate all existing sessions for this user
	if err := h.store.Users.BumpTokenVersion(r.Context(), id); err != nil {
		slog.ErrorContext(r.Context(), "failed to bump token version on password reset", "user_id", id, "err", err)
	}

	h.auditLog(r, "user.reset_password", "user", u.ID, oldUser, u)

	h.notifySecurityEvent(r.Context(), u, "password_reset",
		"Your password was reset",
		fmt.Sprintf("Your password was reset by an administrator (%s). If you did not request this change, contact your administrator immediately.", claims.Sub))

	writeJSON(w, http.StatusOK, map[string]string{"message": "Password reset successfully"})
}

func (h *Handler) DeleteUser(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	// Get old user state for audit
	oldUser, _ := h.store.Users.GetByID(r.Context(), id)

	if err := h.store.Users.Delete(r.Context(), id); err != nil {
		writeError(w, r, http.StatusInternalServerError, "failed to delete user")
		return
	}

	h.auditLog(r, "user.delete", "user", id, oldUser, nil)

	w.WriteHeader(http.StatusNoContent)
}
