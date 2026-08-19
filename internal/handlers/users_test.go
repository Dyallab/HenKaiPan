package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"aspm/internal/assert"
	"aspm/internal/auth"
	aspmmw "aspm/internal/middleware"
	"aspm/internal/models"
	"aspm/internal/repository"

	"github.com/go-chi/chi/v5"
	"github.com/redis/go-redis/v9"
	"github.com/jackc/pgx/v5"

	"github.com/alicebob/miniredis/v2"
	"golang.org/x/crypto/bcrypt"
)

func TestMain(m *testing.M) {
	auth.SetSecret("test-secret-for-handler-tests")
	m.Run()
}

// ── Mock UserRepository ─────────────────────────────────────────────────────

type mockUserRepo struct {
	users          map[string]*models.User
	creds          map[string]*repository.Credentials
	tv             map[string]int
	bumpCount      int
	passwordHash   map[string]string // username → password_hash
}

func newMockUserRepo() *mockUserRepo {
	return &mockUserRepo{
		users:        make(map[string]*models.User),
		creds:        make(map[string]*repository.Credentials),
		tv:           make(map[string]int),
		passwordHash: make(map[string]string),
	}
}

func (m *mockUserRepo) seed(id, username, email, role string, active bool) {
	m.users[id] = &models.User{
		ID: id, Username: username, Email: email, Role: role,
		IsActive: active, CreatedAt: time.Now(),
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	m.passwordHash[username] = string(hash)
	m.creds[username] = &repository.Credentials{
		ID: id, PasswordHash: string(hash), Role: role,
		TokenVersion: 0, IsActive: active,
	}
	m.tv[id] = 0
}

func (m *mockUserRepo) List(context.Context) ([]models.User, error) {
	var out []models.User
	for _, u := range m.users {
		out = append(out, *u)
	}
	return out, nil
}

func (m *mockUserRepo) GetByID(_ context.Context, id string) (*models.User, error) {
	u, ok := m.users[id]
	if !ok {
		return nil, pgx.ErrNoRows
	}
	return u, nil
}

func (m *mockUserRepo) GetUserByEmail(_ context.Context, email string) (*models.User, error) {
	for _, u := range m.users {
		if u.Email == email {
			return u, nil
		}
	}
	return nil, pgx.ErrNoRows
}

func (m *mockUserRepo) Create(_ context.Context, u repository.UserCreate) (*models.User, error) {
	id := "new-" + u.Username
	out := &models.User{
		ID: id, Username: u.Username, Email: u.Email,
		Role: u.Role, IsActive: true, CreatedAt: time.Now(),
	}
	m.users[id] = out
	m.passwordHash[u.Username] = u.PasswordHash
	m.creds[u.Username] = &repository.Credentials{
		ID: id, PasswordHash: u.PasswordHash, Role: u.Role,
		TokenVersion: 0, IsActive: true,
	}
	m.tv[id] = 0
	return out, nil
}

func (m *mockUserRepo) Update(_ context.Context, id string, upd repository.UserUpdate) (*models.User, error) {
	u, ok := m.users[id]
	if !ok {
		return nil, pgx.ErrNoRows
	}
	if upd.Email != nil {
		u.Email = *upd.Email
	}
	if upd.Role != nil {
		u.Role = *upd.Role
	}
	if upd.PasswordHash != nil {
		m.passwordHash[u.Username] = *upd.PasswordHash
		m.creds[u.Username].PasswordHash = *upd.PasswordHash
	}
	if upd.IsActive != nil {
		u.IsActive = *upd.IsActive
		m.creds[u.Username].IsActive = *upd.IsActive
	}
	// Return a copy
	updated := *u
	return &updated, nil
}

func (m *mockUserRepo) Delete(_ context.Context, id string) error {
	delete(m.users, id)
	return nil
}

func (m *mockUserRepo) GetCredentials(_ context.Context, username string) (*repository.Credentials, error) {
	c, ok := m.creds[username]
	if !ok {
		return nil, pgx.ErrNoRows
	}
	return c, nil
}

func (m *mockUserRepo) UpdateLastLogin(_ context.Context, id string) error {
	if u, ok := m.users[id]; ok {
		now := time.Now()
		u.LastLogin = &now
	}
	return nil
}

func (m *mockUserRepo) Count(context.Context) (int, error) {
	return len(m.users), nil
}

func (m *mockUserRepo) IsActive(_ context.Context, id string) (bool, error) {
	u, ok := m.users[id]
	if !ok {
		return false, pgx.ErrNoRows
	}
	return u.IsActive, nil
}

func (m *mockUserRepo) GetTokenVersion(_ context.Context, id string) (int, error) {
	tv, ok := m.tv[id]
	if !ok {
		return 0, pgx.ErrNoRows
	}
	return tv, nil
}

func (m *mockUserRepo) BumpTokenVersion(_ context.Context, id string) error {
	m.bumpCount++
	if _, ok := m.tv[id]; ok {
		m.tv[id]++
	}
	return nil
}

func (m *mockUserRepo) GetPasswordHashByID(_ context.Context, id string) (string, error) {
	for _, u := range m.users {
		if u.ID == id {
			return m.passwordHash[u.Username], nil
		}
	}
	return "", pgx.ErrNoRows
}

func (m *mockUserRepo) GetUserBySSOIdentity(_ context.Context, provider, subject string) (*models.User, error) {
	return nil, pgx.ErrNoRows
}

func (m *mockUserRepo) LinkSSOIdentity(_ context.Context, id, provider, subject string) error {
	return nil
}

// ── Mock NotificationRepository ─────────────────────────────────────────────

type mockNotificationRepo struct{}

func (m *mockNotificationRepo) Create(_ context.Context, n repository.NotificationCreate) (*models.UserNotification, error) {
	// Return error so notifySecurityEvent skips events.Publish (Redis/SSE not available in tests)
	return nil, errors.New("not implemented")
}

func (m *mockNotificationRepo) List(_ context.Context, _ repository.NotificationFilter) ([]models.UserNotification, int, error) {
	return nil, 0, nil
}

func (m *mockNotificationRepo) MarkAsRead(_ context.Context, _, _ string) error  { return nil }
func (m *mockNotificationRepo) MarkAllAsRead(_ context.Context, _ string) error  { return nil }
func (m *mockNotificationRepo) GetUnreadCount(_ context.Context, _ string) (int, error) {
	return 0, nil
}

// ── Mock AuditRepository ────────────────────────────────────────────────────

type mockAuditRepo struct {
	entries []repository.AuditLogEntry
}

func (m *mockAuditRepo) Log(_ context.Context, entry repository.AuditLogEntry) error {
	m.entries = append(m.entries, entry)
	return nil
}

func (m *mockAuditRepo) List(_ context.Context, _ repository.AuditFilter) ([]models.AuditLog, int, error) {
	return nil, 0, nil
}

// ── Helpers ─────────────────────────────────────────────────────────────────

func newTestHandler(users *mockUserRepo) *Handler {
	return &Handler{
		store: repository.Stores{
			Users:         users,
			Notifications: &mockNotificationRepo{},
			Audit:         &mockAuditRepo{},
		},
		emailEnabled: false,
	}
}

func chiReq(method, path, id string, body interface{}) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", id)

	var buf *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		buf = bytes.NewReader(b)
	}

	req := httptest.NewRequest(method, path, buf)
	if buf != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
}

func setupMiniredis(t *testing.T) *miniredis.Miniredis {
	t.Helper()
	if aspmmw.Rdb != nil {
		aspmmw.Rdb.Close()
	}
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	aspmmw.Rdb = redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() {
		aspmmw.Rdb.Close()
		mr.Close()
	})
	return mr
}

// ── UpdateUser: is_active tests ─────────────────────────────────────────────

func TestUpdateUser_DeactivateUser(t *testing.T) {
	users := newMockUserRepo()
	users.seed("usr-1", "alice", "alice@example.com", "admin", true)

	h := newTestHandler(users)

	isActive := false
	req := chiReq(http.MethodPatch, "/api/users/usr-1", "usr-1", map[string]bool{
		"is_active": isActive,
	})
	rec := httptest.NewRecorder()

	h.UpdateUser(rec, req)

	assert.Equal(t, rec.Code, http.StatusOK)

	// Verify the user was deactivated in the store
	updated := users.users["usr-1"]
	assert.False(t, updated.IsActive)

	// Verify token_version was bumped
	assert.True(t, users.bumpCount >= 1 || users.tv["usr-1"] > 0)
}

func TestUpdateUser_ActivateUser(t *testing.T) {
	users := newMockUserRepo()
	users.seed("usr-1", "bob", "bob@example.com", "viewer", false)

	h := newTestHandler(users)

	req := chiReq(http.MethodPatch, "/api/users/usr-1", "usr-1", map[string]bool{
		"is_active": true,
	})
	rec := httptest.NewRecorder()

	h.UpdateUser(rec, req)

	assert.Equal(t, rec.Code, http.StatusOK)

	updated := users.users["usr-1"]
	assert.True(t, updated.IsActive)

	// Verify token_version was bumped on reactivation
	assert.True(t, users.tv["usr-1"] > 0)
}

func TestUpdateUser_DeactivateNonExistentUser(t *testing.T) {
	users := newMockUserRepo()
	users.seed("usr-1", "alice", "alice@example.com", "admin", true)

	h := newTestHandler(users)

	req := chiReq(http.MethodPatch, "/api/users/nonexistent", "nonexistent", map[string]bool{
		"is_active": false,
	})
	rec := httptest.NewRecorder()

	h.UpdateUser(rec, req)

	assert.Equal(t, rec.Code, http.StatusNotFound)
}

// ── Login: disabled user tests ──────────────────────────────────────────────

func TestLogin_DisabledUser_Returns403(t *testing.T) {
	setupMiniredis(t)

	users := newMockUserRepo()
	users.seed("usr-1", "alice", "alice@example.com", "admin", false)

	h := newTestHandler(users)

	body := map[string]string{
		"username": "alice",
		"password": "password123",
	}
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	h.Login(rec, req)

	assert.Equal(t, rec.Code, http.StatusForbidden)

	var resp map[string]string
	json.Unmarshal(rec.Body.Bytes(), &resp)
	assert.Equal(t, resp["message"], "account is disabled")
}

func TestLogin_ActiveUser_Succeeds(t *testing.T) {
	setupMiniredis(t)

	users := newMockUserRepo()
	users.seed("usr-1", "alice", "alice@example.com", "admin", true)

	h := newTestHandler(users)

	body := map[string]string{
		"username": "alice",
		"password": "password123",
	}
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	h.Login(rec, req)

	assert.Equal(t, rec.Code, http.StatusOK)

	var resp map[string]string
	json.Unmarshal(rec.Body.Bytes(), &resp)
	assert.Equal(t, resp["role"], "admin")
}

// ── ListUsers: includes is_active ───────────────────────────────────────────

func TestListUsers_ReturnsIsActiveField(t *testing.T) {
	users := newMockUserRepo()
	users.seed("usr-1", "alice", "alice@example.com", "admin", true)
	users.seed("usr-2", "bob", "bob@example.com", "viewer", false)

	h := newTestHandler(users)

	req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
	rec := httptest.NewRecorder()

	h.ListUsers(rec, req)

	assert.Equal(t, rec.Code, http.StatusOK)

	var resp []map[string]any
	json.Unmarshal(rec.Body.Bytes(), &resp)
	assert.Equal(t, len(resp), 2)

	for _, u := range resp {
		_, ok := u["is_active"]
		assert.True(t, ok)
	}
}
