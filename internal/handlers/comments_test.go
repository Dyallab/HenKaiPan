package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"aspm/internal/assert"
	"aspm/internal/auth"
	"aspm/internal/models"
	"aspm/internal/repository"
	"aspm/internal/tasks"

	"github.com/go-chi/chi/v5"
	"github.com/hibiken/asynq"
)

// ── extractMentions ─────────────────────────────────────────────────────────

func TestExtractMentions(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    []string
	}{
		{name: "single mention", content: "hey @alice please look", want: []string{"alice"}},
		{name: "multiple mentions", content: "@alice and @bob take a look", want: []string{"alice", "bob"}},
		{name: "exact duplicates removed, case variants kept", content: "@alice cc @Alice again @alice", want: []string{"alice", "Alice"}},
		{name: "email address is not a mention", content: "contact foo@bar.com", want: nil},
		{name: "trailing punctuation excluded", content: "thanks @alice!", want: []string{"alice"}},
		{name: "too short ignored", content: "hi @a", want: nil},
		{name: "no space after @ ignored", content: "reach me @ home", want: nil},
		{name: "mention at start of line", content: "first line\n@bob please review", want: []string{"bob"}},
		{name: "no mentions", content: "nothing to see here", want: nil},
		{name: "underscores allowed", content: "@alice_smith ok?", want: []string{"alice_smith"}},
		{name: "digits allowed", content: "@user123 hi", want: []string{"user123"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractMentions(tt.content)
			assert.Equal(t, got, tt.want)
		})
	}
}

// ── Mocks ───────────────────────────────────────────────────────────────────

type stubAppsRepo struct {
	repository.AppRepository
}

func (s *stubAppsRepo) CreateFindingComment(_ context.Context, c repository.CommentCreate) (*repository.FindingComment, error) {
	return &repository.FindingComment{
		ID:        1,
		FindingID: c.FindingID,
		UserID:    c.UserID,
		Content:   c.Content,
	}, nil
}

type stubFindingsRepo struct {
	repository.FindingRepository
	finding *models.Finding
}

func (s *stubFindingsRepo) GetByID(context.Context, string) (*models.Finding, error) {
	return s.finding, nil
}

type recordingNotifications struct {
	repository.NotificationRepository
	created []repository.NotificationCreate
}

func (r *recordingNotifications) Create(_ context.Context, n repository.NotificationCreate) (*models.UserNotification, error) {
	r.created = append(r.created, n)
	return &models.UserNotification{
		ID:      "notif-" + n.UserID,
		UserID:  n.UserID,
		Title:   n.Title,
		Message: n.Message,
		Type:    n.Type,
	}, nil
}

// ── Fixture ─────────────────────────────────────────────────────────────────

type commentsFixture struct {
	h             *Handler
	users         *mockUserRepo
	notifs        *recordingNotifications
	miniRedisAddr string
}

func newCommentsFixture(t *testing.T) *commentsFixture {
	t.Helper()

	mr := setupMiniredis(t)
	queue := asynq.NewClient(asynq.RedisClientOpt{Addr: mr.Addr()})
	t.Cleanup(func() { queue.Close() })

	users := newMockUserRepo()
	users.seed("usr-alice", "alice", "alice@example.com", "analyst", true)
	users.seed("usr-bob", "bob", "bob@example.com", "admin", true)
	users.seed("usr-carol", "carol", "carol@example.com", "viewer", false)

	notifs := &recordingNotifications{}
	h := &Handler{
		store: repository.Stores{
			Apps:          &stubAppsRepo{},
			Findings:      &stubFindingsRepo{finding: &models.Finding{ID: "fnd-1", Title: "SQL injection in login"}},
			Users:         users,
			Notifications: notifs,
		},
		queue:        queue,
		frontendURL:  "http://localhost:4173",
		emailEnabled: true,
	}
	return &commentsFixture{h: h, users: users, notifs: notifs, miniRedisAddr: mr.Addr()}
}

func (f *commentsFixture) postComment(t *testing.T, authorID, authorUsername, content string) *httptest.ResponseRecorder {
	t.Helper()

	token, err := auth.IssueToken(authorUsername, "admin", authorID, 0)
	assert.NoError(t, err)

	body, err := json.Marshal(map[string]string{"content": content})
	assert.NoError(t, err)

	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("findingID", "fnd-1")
	req := httptest.NewRequest(http.MethodPost, "/api/findings/fnd-1/comments", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	rec := httptest.NewRecorder()
	auth.JWTMiddleware(http.HandlerFunc(f.h.CreateFindingComment)).ServeHTTP(rec, req)
	return rec
}

// pendingEmailTasks lists pending tasks in the default queue, decoded.
func (f *commentsFixture) pendingEmailTasks(t *testing.T) []tasks.EmailSendPayload {
	t.Helper()

	inspector := asynq.NewInspector(asynq.RedisClientOpt{Addr: f.miniRedisAddr})
	defer inspector.Close()
	infos, err := inspector.ListPendingTasks("default")
	if errors.Is(err, asynq.ErrQueueNotFound) {
		return nil
	}
	assert.NoError(t, err)

	var out []tasks.EmailSendPayload
	for _, info := range infos {
		if info.Type != tasks.TypeEmailSend {
			continue
		}
		var p tasks.EmailSendPayload
		if err := json.Unmarshal(info.Payload, &p); err != nil {
			t.Fatalf("unmarshal email payload: %v", err)
		}
		out = append(out, p)
	}
	return out
}

// ── Tests ───────────────────────────────────────────────────────────────────

func TestCreateFindingComment_MentionSendsNotificationAndEmail(t *testing.T) {
	f := newCommentsFixture(t)

	rec := f.postComment(t, "usr-bob", "bob", "hey @alice, can you review this?")
	assert.Equal(t, rec.Code, http.StatusCreated)

	// In-app notification created for alice.
	assert.Equal(t, len(f.notifs.created), 1)
	n := f.notifs.created[0]
	assert.Equal(t, n.UserID, "usr-alice")
	assert.Equal(t, n.Type, "comment_mention")

	// Email enqueued for alice.
	emails := f.pendingEmailTasks(t)
	assert.Equal(t, len(emails), 1)
	assert.Equal(t, emails[0].To, []string{"alice@example.com"})
	assert.True(t, strings.Contains(emails[0].Subject, "mentioned"))
	assert.True(t, strings.Contains(emails[0].Body, "bob mentioned you"))
	assert.True(t, strings.Contains(emails[0].Body, "http://localhost:4173/dashboard/findings/detail?id=fnd-1"))
}

func TestCreateFindingComment_SelfMentionSkipped(t *testing.T) {
	f := newCommentsFixture(t)

	rec := f.postComment(t, "usr-bob", "bob", "fixed by @bob himself")
	assert.Equal(t, rec.Code, http.StatusCreated)

	assert.Equal(t, len(f.notifs.created), 0)
	assert.Equal(t, len(f.pendingEmailTasks(t)), 0)
}

func TestCreateFindingComment_UnknownMentionIgnored(t *testing.T) {
	f := newCommentsFixture(t)

	rec := f.postComment(t, "usr-bob", "bob", "cc @ghost who does not exist")
	assert.Equal(t, rec.Code, http.StatusCreated)

	assert.Equal(t, len(f.notifs.created), 0)
	assert.Equal(t, len(f.pendingEmailTasks(t)), 0)
}

func TestCreateFindingComment_InactiveUserSkipped(t *testing.T) {
	f := newCommentsFixture(t)

	rec := f.postComment(t, "usr-bob", "bob", "fyi @carol")
	assert.Equal(t, rec.Code, http.StatusCreated)

	assert.Equal(t, len(f.notifs.created), 0)
	assert.Equal(t, len(f.pendingEmailTasks(t)), 0)
}

func TestCreateFindingComment_NoMentionsNoSideEffects(t *testing.T) {
	f := newCommentsFixture(t)

	rec := f.postComment(t, "usr-bob", "bob", "plain comment, nothing special")
	assert.Equal(t, rec.Code, http.StatusCreated)

	assert.Equal(t, len(f.notifs.created), 0)
	assert.Equal(t, len(f.pendingEmailTasks(t)), 0)
}

func TestCreateFindingComment_Unauthorized(t *testing.T) {
	f := newCommentsFixture(t)

	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("findingID", "fnd-1")
	req := httptest.NewRequest(http.MethodPost, "/api/findings/fnd-1/comments", strings.NewReader(`{"content":"hi"}`))
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	rec := httptest.NewRecorder()
	http.HandlerFunc(f.h.CreateFindingComment).ServeHTTP(rec, req)
	assert.Equal(t, rec.Code, http.StatusUnauthorized)
}
