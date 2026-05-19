package handlers

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"aspm/internal/auth"
	"aspm/internal/repository"

	"github.com/go-chi/chi/v5"
	"golang.org/x/crypto/bcrypt"
)

const (
	tokenPrefix  = "hkp_"
	tokenByteLen = 32 // 64 hex chars
)

// generateToken creates a cryptographically random token "hkp_<hex>".
func generateToken() (raw string, prefix string, err error) {
	b := make([]byte, tokenByteLen)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	raw = tokenPrefix + hex.EncodeToString(b)
	prefix = raw[:12] // e.g. "hkp_abc123de"
	return raw, prefix, nil
}

func hashToken(raw string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(raw), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// ── Context key for API token ─────────────────────────────────────────────

type ctxKey string

const tokenCtxKey ctxKey = "api_token"

// apiKeyFromContext retrieves the authenticated API token from the request context.
func apiKeyFromContext(r *http.Request) *repository.Token {
	if t, ok := r.Context().Value(tokenCtxKey).(*repository.Token); ok {
		return t
	}
	return nil
}

// ── Token Management Handlers ──────────────────────────────────────────────

// CreateToken generates a new API token and returns it ONCE.
func (h *Handler) CreateToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name      string `json:"name"`
		ProjectID string `json:"project_id,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}

	claims := auth.GetClaims(r)
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	raw, prefix, err := generateToken()
	if err != nil {
		h.writeInternal(w, r, err, "failed to generate token")
		return
	}

	hashed, err := hashToken(raw)
	if err != nil {
		h.writeInternal(w, r, err, "failed to hash token")
		return
	}

	var projectID *string
	if req.ProjectID != "" {
		projectID = &req.ProjectID
	}

	t, err := h.store.Tokens.Create(r.Context(), repository.TokenCreate{
		Name:      req.Name,
		ProjectID: projectID,
		CreatedBy: claims.UserID,
	}, hashed, prefix)
	if err != nil {
		h.writeInternal(w, r, err, "failed to create token")
		return
	}

	h.auditLog(r, "api_token.create", "api_token", t.ID, nil, map[string]any{
		"name":       req.Name,
		"project_id": projectID,
	})

	writeJSON(w, http.StatusCreated, map[string]any{
		"token":  raw, // shown only once
		"id":     t.ID,
		"name":   t.Name,
		"prefix": t.Prefix,
	})
}

// ListTokens returns all API tokens owned by the current user (never includes raw values).
func (h *Handler) ListTokens(w http.ResponseWriter, r *http.Request) {
	claims := auth.GetClaims(r)
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	tokens, err := h.store.Tokens.List(r.Context(), claims.UserID)
	if err != nil {
		h.writeInternal(w, r, err, "failed to list tokens")
		return
	}

	// Ensure we return an empty array, not null, for consistent frontend handling
	if tokens == nil {
		tokens = []repository.Token{}
	}

	writeJSON(w, http.StatusOK, map[string]any{"tokens": tokens})
}

// DeleteToken revokes an API token. Only the creator can revoke.
func (h *Handler) DeleteToken(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "token id required")
		return
	}

	claims := auth.GetClaims(r)
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if err := h.store.Tokens.Delete(r.Context(), id, claims.UserID); err != nil {
		writeError(w, http.StatusNotFound, "token not found")
		return
	}

	h.auditLog(r, "api_token.delete", "api_token", id, nil, nil)
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

// ── External Scan Endpoints ────────────────────────────────────────────────

// CreateExternalScan triggers a scan from an external CI/CD system.
// Authenticated via X-API-Key header (not JWT).
func (h *Handler) CreateExternalScan(w http.ResponseWriter, r *http.Request) {
	token := apiKeyFromContext(r)
	if token == nil {
		writeError(w, http.StatusUnauthorized, "valid API key required")
		return
	}

	var req struct {
		ProjectID string   `json:"project_id"`
		RepoURL   string   `json:"repo_url"`
		Scanners  []string `json:"scanners"`
		Branch    string   `json:"branch,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	if req.ProjectID == "" {
		writeError(w, http.StatusBadRequest, "project_id is required")
		return
	}
	if len(req.Scanners) == 0 {
		req.Scanners = []string{"all"}
	}

	// Scope check: if token is project-scoped, it must match the requested project
	if token.ProjectID != nil && *token.ProjectID != req.ProjectID {
		writeError(w, http.StatusForbidden, "token is not scoped to this project")
		return
	}

	// Resolve scanner names (handle packs like "all", "sast", etc.)
	scannerNames, err := resolveScanners(req.Scanners)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Build target: repo_url falls back to project_id, optionally with branch
	target := req.RepoURL
	if target == "" {
		target = req.ProjectID // worker resolves from project config
	}
	if req.Branch != "" {
		target = target + "#" + req.Branch
	}

	// Reuse shared scan creation logic
	scanIDs, batchID, err := h.createScanRecords(r.Context(), target, scannerNames, &req.ProjectID, "")
	if err != nil {
		h.writeInternal(w, r, err, "failed to create scan records")
		return
	}

	// Update token last_used_at
	_ = h.store.Tokens.UpdateLastUsed(r.Context(), token.ID)

	slog.InfoContext(r.Context(), "external scan created",
		"project_id", req.ProjectID,
		"scanners", scannerNames,
		"batch_id", batchID,
		"scan_ids", scanIDs,
	)

	writeJSON(w, http.StatusAccepted, map[string]any{
		"scan_ids": scanIDs,
		"batch_id": batchID,
		"status":   "accepted",
	})
}

// GetExternalScanStatus returns the status and findings of a scan triggered externally.
func (h *Handler) GetExternalScanStatus(w http.ResponseWriter, r *http.Request) {
	token := apiKeyFromContext(r)
	if token == nil {
		writeError(w, http.StatusUnauthorized, "valid API key required")
		return
	}

	scanID := chi.URLParam(r, "id")
	if scanID == "" {
		writeError(w, http.StatusBadRequest, "scan id required")
		return
	}

	scan, err := h.store.Scans.Get(r.Context(), scanID)
	if err != nil {
		writeError(w, http.StatusNotFound, "scan not found")
		return
	}

	// Scope check
	if token.ProjectID != nil && scan.ProjectID != nil && *token.ProjectID != *scan.ProjectID {
		writeError(w, http.StatusForbidden, "token is not scoped to this project")
		return
	}

	findings, err := h.store.Findings.GetByScanID(r.Context(), scanID)
	if err != nil {
		findings = nil
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"scan":     scan,
		"findings": findings,
	})
}

// ── API Key Auth Middleware ────────────────────────────────────────────────

// APIKeyAuth is a middleware that authenticates requests via the X-API-Key header.
// It looks up the token by prefix, verifies the bcrypt hash, and stores the token
// in the request context. Returns 401 on any authentication failure.
//
// Should be applied only to /api/v1/scans/* routes. Platform endpoints (JWT)
// use a separate middleware stack and never see this middleware.
func APIKeyAuth(store repository.Stores) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw := r.Header.Get("X-API-Key")
			if raw == "" {
				writeError(w, http.StatusUnauthorized, "X-API-Key header required")
				return
			}

			// Extract prefix: first 12 characters of the raw token
			prefix := raw
			if len(raw) >= 12 {
				prefix = raw[:12]
			}

			token, err := store.Tokens.GetByPrefix(r.Context(), prefix)
			if err != nil || token == nil {
				writeError(w, http.StatusUnauthorized, "invalid API key")
				return
			}

			// Check expiration
			if token.ExpiresAt != nil && time.Now().After(*token.ExpiresAt) {
				writeError(w, http.StatusUnauthorized, "API key has expired")
				return
			}

			// Bcrypt comparison of raw token against stored hash
			if bcrypt.CompareHashAndPassword([]byte(token.Hash), []byte(raw)) != nil {
				writeError(w, http.StatusUnauthorized, "invalid API key")
				return
			}

			ctx := context.WithValue(r.Context(), tokenCtxKey, token)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
