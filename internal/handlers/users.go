package handlers

import (
	"encoding/json"
	"net/http"

	"aspm/internal/repository"

	"github.com/go-chi/chi/v5"
	"golang.org/x/crypto/bcrypt"
)

func (h *Handler) ListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := h.store.Users.List(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list users")
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
		writeError(w, http.StatusBadRequest, "username, email, and password required")
		return
	}
	if body.Role == "" {
		body.Role = "analyst"
	}
	validRole := map[string]bool{"admin": true, "analyst": true, "viewer": true}
	if !validRole[body.Role] {
		writeError(w, http.StatusBadRequest, "role must be admin, analyst, or viewer")
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(body.Password), bcrypt.DefaultCost)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "password hash error")
		return
	}

	u, err := h.store.Users.Create(r.Context(), repository.UserCreate{
		Username: body.Username, Email: body.Email,
		PasswordHash: string(hash), Role: body.Role,
	})
	if err != nil {
		writeError(w, http.StatusConflict, "username or email already exists")
		return
	}
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
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}

	if body.Role != nil {
		validRole := map[string]bool{"admin": true, "analyst": true, "viewer": true}
		if !validRole[*body.Role] {
			writeError(w, http.StatusBadRequest, "role must be admin, analyst, or viewer")
			return
		}
	}

	var hashPtr *string
	if body.Password != nil && *body.Password != "" {
		h, err := bcrypt.GenerateFromPassword([]byte(*body.Password), bcrypt.DefaultCost)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "password hash error")
			return
		}
		s := string(h)
		hashPtr = &s
	}

	u, err := h.store.Users.Update(r.Context(), id, repository.UserUpdate{
		Email: body.Email, Role: body.Role, PasswordHash: hashPtr,
	})
	if err != nil {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}
	writeJSON(w, http.StatusOK, u)
}

func (h *Handler) DeleteUser(w http.ResponseWriter, r *http.Request) {
	if err := h.store.Users.Delete(r.Context(), chi.URLParam(r, "id")); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to delete user")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
