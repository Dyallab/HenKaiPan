package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"aspm/internal/assert"
	"aspm/internal/auth"
	"aspm/internal/repository"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/bcrypt"
)

// ── Mock TokenRepository ──────────────────────────────────────────────────

type mockTokenRepo struct {
	tokens map[string]*repository.Token // keyed by token ID
	hashes map[string]string             // ID → stored hash
}

func newMockTokenRepo() *mockTokenRepo {
	return &mockTokenRepo{
		tokens: make(map[string]*repository.Token),
		hashes: make(map[string]string),
	}
}

func (m *mockTokenRepo) seed(id, name, prefix, hash, createdBy string, projectID *string) {
	now := time.Now()
	m.tokens[id] = &repository.Token{
		ID:        id,
		Name:      name,
		Prefix:    prefix,
		Hash:      hash,
		ProjectID: projectID,
		CreatedBy: &createdBy,
		CreatedAt: now,
		UpdatedAt: now,
	}
	m.hashes[id] = hash
}

func (m *mockTokenRepo) Create(_ context.Context, tok repository.TokenCreate, hash, prefix string) (*repository.Token, error) {
	t := &repository.Token{
		ID:        "tok-" + tok.Name,
		Name:      tok.Name,
		Prefix:    prefix,
		Hash:      hash,
		ProjectID: tok.ProjectID,
		CreatedBy: &tok.CreatedBy,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	m.tokens[t.ID] = t
	m.hashes[t.ID] = hash
	return t, nil
}

func (m *mockTokenRepo) List(_ context.Context, userID string) ([]repository.Token, error) {
	var out []repository.Token
	for _, t := range m.tokens {
		if t.CreatedBy != nil && *t.CreatedBy == userID {
			out = append(out, *t)
		}
	}
	return out, nil
}

func (m *mockTokenRepo) GetByPrefix(_ context.Context, prefix string) (*repository.Token, error) {
	for _, t := range m.tokens {
		if t.Prefix == prefix {
			return t, nil
		}
	}
	return nil, nil
}

func (m *mockTokenRepo) Rotate(_ context.Context, id, userID, hash, prefix string) (*repository.Token, error) {
	t, ok := m.tokens[id]
	if !ok || t.CreatedBy == nil || *t.CreatedBy != userID {
		return nil, pgx.ErrNoRows
	}
	t.Hash = hash
	t.Prefix = prefix
	t.UpdatedAt = time.Now()
	m.hashes[id] = hash
	out := *t
	return &out, nil
}

func (m *mockTokenRepo) Delete(_ context.Context, id, userID string) error {
	t, ok := m.tokens[id]
	if !ok || t.CreatedBy == nil || *t.CreatedBy != userID {
		return pgx.ErrNoRows
	}
	delete(m.tokens, id)
	delete(m.hashes, id)
	return nil
}

func (m *mockTokenRepo) UpdateLastUsed(_ context.Context, id string) error {
	return nil
}

// ── Helpers ───────────────────────────────────────────────────────────────

func newTokenTestHandler(tokens *mockTokenRepo) *Handler {
	return &Handler{
		store: repository.Stores{
			Tokens: tokens,
			Audit:  &mockAuditRepo{},
		},
	}
}

func tokenChiReq(method, path, id string) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", id)
	req := httptest.NewRequest(method, path, nil)
	req.Header.Set("Content-Type", "application/json")
	return req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
}

func rotateWithAuth(h *Handler, tokenID, userID, username string) *httptest.ResponseRecorder {
	jwt, err := auth.IssueToken(username, "admin", userID, 0)
	if err != nil {
		panic(err)
	}
	req := tokenChiReq(http.MethodPost, "/api/v1/tokens/"+tokenID+"/rotate", tokenID)
	req.Header.Set("Authorization", "Bearer "+jwt)
	rec := httptest.NewRecorder()
	auth.JWTMiddleware(http.HandlerFunc(h.RotateToken)).ServeHTTP(rec, req)
	return rec
}

// ── RotateToken tests ─────────────────────────────────────────────────────

func TestRotateToken_Success(t *testing.T) {
	tokens := newMockTokenRepo()
	oldHash, _ := hashToken("hkp_oldddddsecret")
	projectID := "proj-1"
	tokens.seed("tok-1", "ci-deploy", "hkp_olddddd1", oldHash, "usr-1", &projectID)

	h := newTokenTestHandler(tokens)
	rec := rotateWithAuth(h, "tok-1", "usr-1", "alice")

	assert.Equal(t, rec.Code, http.StatusOK)

	var resp map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	raw, ok := resp["token"].(string)
	if !ok || raw == "" {
		t.Fatalf("expected non-empty token in response, got: %v", resp["token"])
	}
	if len(raw) <= 12 || raw[:4] != "hkp_" {
		t.Fatalf("token does not have hkp_ prefix: %s", raw)
	}
	assert.Equal(t, resp["id"], "tok-1")
	assert.Equal(t, resp["name"], "ci-deploy")

	// Old secret must no longer verify against the stored hash
	stored := tokens.hashes["tok-1"]
	if bcrypt.CompareHashAndPassword([]byte(stored), []byte("hkp_oldddddsecret")) == nil {
		t.Fatal("old secret still matches stored hash — rotation did not revoke it")
	}
	// New secret must verify against the stored hash
	if bcrypt.CompareHashAndPassword([]byte(stored), []byte(raw)) != nil {
		t.Fatal("new secret does not match stored hash")
	}

	// Name and project scope preserved
	assert.Equal(t, tokens.tokens["tok-1"].Name, "ci-deploy")
	assert.Equal(t, *tokens.tokens["tok-1"].ProjectID, "proj-1")
}

func TestRotateToken_NotOwner(t *testing.T) {
	tokens := newMockTokenRepo()
	oldHash, _ := hashToken("hkp_oldddddsecret")
	tokens.seed("tok-1", "ci-deploy", "hkp_olddddd1", oldHash, "usr-owner", nil)

	h := newTokenTestHandler(tokens)
	rec := rotateWithAuth(h, "tok-1", "usr-other", "bob")

	assert.Equal(t, rec.Code, http.StatusNotFound)
}

func TestRotateToken_NotFound(t *testing.T) {
	tokens := newMockTokenRepo()
	h := newTokenTestHandler(tokens)
	rec := rotateWithAuth(h, "tok-nonexistent", "usr-1", "alice")

	assert.Equal(t, rec.Code, http.StatusNotFound)
}

func TestRotateToken_NoAuth(t *testing.T) {
	tokens := newMockTokenRepo()
	oldHash, _ := hashToken("hkp_oldddddsecret")
	tokens.seed("tok-1", "ci-deploy", "hkp_olddddd1", oldHash, "usr-1", nil)

	h := newTokenTestHandler(tokens)
	req := tokenChiReq(http.MethodPost, "/api/v1/tokens/tok-1/rotate", "tok-1")
	rec := httptest.NewRecorder()
	h.RotateToken(rec, req)

	assert.Equal(t, rec.Code, http.StatusUnauthorized)
}
