package handlers

import (
	"encoding/json"
	"net/http"

	"aspm/internal/repository"
	"aspm/internal/validation"

	"github.com/go-chi/chi/v5"
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
		Email    *string `json:"email"`
		Role     *string `json:"role"`
		Password *string `json:"password"`
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

	var hashPtr *string
	if body.Password != nil && *body.Password != "" {
		h, err := bcrypt.GenerateFromPassword([]byte(*body.Password), bcrypt.DefaultCost)
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "password hash error")
			return
		}
		s := string(h)
		hashPtr = &s
	}

	// Get old user state for audit
	oldUser, _ := h.store.Users.GetByID(r.Context(), id)

	u, err := h.store.Users.Update(r.Context(), id, repository.UserUpdate{
		Email: body.Email, Role: body.Role, PasswordHash: hashPtr,
	})
	if err != nil {
		writeError(w, r, http.StatusNotFound, "user not found")
		return
	}

	h.auditLog(r, "user.update", "user", u.ID, oldUser, u)

	writeJSON(w, http.StatusOK, u)
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
