//go:build integration

package repository

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"aspm/internal/assert"
	"aspm/internal/datascope"
	"aspm/internal/testdb"
)

// testEnv bundles the pool, stores, and context shared by every test.
type testEnv struct {
	ctx    context.Context
	pool   *pgxpool.Pool
	stores Stores
}

// newTestEnv connects to the test database, resets the seed tables, and
// wires the repository stores. Each test starts from a clean slate.
func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	pool := testdb.Connect(t)
	testdb.Reset(t, pool)
	return &testEnv{
		ctx:    context.Background(),
		pool:   pool,
		stores: NewPostgresStores(pool, ""),
	}
}

// seedIDs holds the IDs of the demo-data chain inserted by seedBase.
type seedIDs struct {
	teamID    string
	userID    string
	appID     string
	projectID string
	scanID    string
	findingID string
}

// seedBase inserts the FK chain team → user → app → project → scan → finding
// (mirroring scripts/seed-demo.sql) so tests can exercise dependent tables.
func seedBase(t *testing.T, pool *pgxpool.Pool) seedIDs {
	t.Helper()
	ids := seedIDs{
		teamID:    uuid.NewString(),
		userID:    uuid.NewString(),
		appID:     uuid.NewString(),
		projectID: uuid.NewString(),
		scanID:    uuid.NewString(),
		findingID: uuid.NewString(),
	}
	inserts := []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO teams (id, name) VALUES ($1, $2)`, []any{ids.teamID, "team-" + ids.teamID}},
		{`INSERT INTO users (id, username, email, password_hash, role) VALUES ($1, $2, $3, $4, $5)`, []any{ids.userID, "user-" + ids.userID, ids.userID + "@test.local", "hash", "viewer"}},
		{`INSERT INTO apps (id, name, team_id) VALUES ($1, $2, $3)`, []any{ids.appID, "app-" + ids.appID, ids.teamID}},
		{`INSERT INTO projects (id, name, app_id) VALUES ($1, $2, $3)`, []any{ids.projectID, "proj-" + ids.projectID, ids.appID}},
		{`INSERT INTO scans (id, project_id, scanner, status, target, scan_batch_id) VALUES ($1, $2, $3, $4, $5, gen_random_uuid())`, []any{ids.scanID, ids.projectID, "semgrep", "completed", "https://example.com/repo"}},
		{`INSERT INTO findings (id, scan_id, project_id, scanner, rule_id, title, severity, file_path, line_start, line_end, status, fingerprint) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`, []any{ids.findingID, ids.scanID, ids.projectID, "semgrep", "rule-1", "Test finding", "high", "src/main.go", 1, 2, "open", "fp-" + ids.findingID}},
	}
	for _, ins := range inserts {
		if _, err := pool.Exec(context.Background(), ins.sql, ins.args...); err != nil {
			t.Fatalf("seed insert: %v", err)
		}
	}
	return ids
}

// ── Finding comments ──────────────────────────────────────────────────────────

func TestFindingCommentsCreateGetDelete(t *testing.T) {
	env := newTestEnv(t)
	ids := seedBase(t, env.pool)

	comment, err := env.stores.Apps.CreateFindingComment(env.ctx, CommentCreate{
		FindingID: ids.findingID,
		UserID:    ids.userID,
		Content:   "needs review",
	})
	assert.NoError(t, err)
	// id is BIGSERIAL — the test never supplies it.
	assert.True(t, comment.ID > 0)
	assert.Equal(t, comment.FindingID, ids.findingID)
	assert.Equal(t, comment.UserID, ids.userID)
	assert.Equal(t, comment.Username, "user-"+ids.userID)
	assert.Equal(t, comment.Content, "needs review")
	assert.False(t, comment.CreatedAt.IsZero())
	assert.False(t, comment.UpdatedAt.IsZero())

	comments, err := env.stores.Apps.GetFindingComments(env.ctx, ids.findingID)
	assert.NoError(t, err)
	assert.Equal(t, len(comments), 1)
	assert.Equal(t, comments[0].ID, comment.ID)

	assert.NoError(t, env.stores.Apps.DeleteFindingComment(env.ctx, comment.ID))

	comments, err = env.stores.Apps.GetFindingComments(env.ctx, ids.findingID)
	assert.NoError(t, err)
	assert.Equal(t, len(comments), 0)
}

func TestFindingCommentsRejectEmptyContent(t *testing.T) {
	env := newTestEnv(t)
	ids := seedBase(t, env.pool)

	_, err := env.stores.Apps.CreateFindingComment(env.ctx, CommentCreate{
		FindingID: ids.findingID,
		UserID:    ids.userID,
		Content:   "",
	})
	assert.NotNil(t, err)
	pgErr := assert.ErrorAs[*pgconn.PgError](t, err)
	assert.Equal(t, pgErr.Code, "23514") // check_violation — content CHECK (char_length > 0)
}

// ── Risk acceptances ──────────────────────────────────────────────────────────

func TestRiskAcceptanceCreateApproveReject(t *testing.T) {
	env := newTestEnv(t)
	ids := seedBase(t, env.pool)

	// approved_by has an FK to users — the approver must exist.
	approverID := uuid.NewString()
	if _, err := env.pool.Exec(env.ctx,
		`INSERT INTO users (id, username, email, password_hash, role) VALUES ($1, $2, $3, $4, $5)`,
		approverID, "approver-"+approverID, approverID+"@test.local", "hash", "admin"); err != nil {
		t.Fatalf("insert approver: %v", err)
	}

	ra, err := env.stores.RiskAcceptance.Create(env.ctx, RiskAcceptanceCreate{
		FindingID: ids.findingID,
		UserID:    ids.userID,
		Rationale: "low risk, dev-only tool",
		ExpiresAt: time.Now().AddDate(0, 3, 0),
		Status:    "pending",
	})
	assert.NoError(t, err)
	assert.NotEqual(t, ra.ID, "")
	assert.Equal(t, ra.Status, "pending")
	assert.Nil(t, ra.ApprovedBy)
	assert.Nil(t, ra.ApprovedAt)
	assert.False(t, ra.CreatedAt.IsZero())

	// NOW() is the transaction start time; a short pause guarantees the
	// updated_at bump is observable.
	time.Sleep(10 * time.Millisecond)

	assert.NoError(t, env.stores.RiskAcceptance.Approve(env.ctx, ra.ID, approverID, "looks fine"))

	got, err := env.stores.RiskAcceptance.GetByFindingID(env.ctx, ids.findingID)
	assert.NoError(t, err)
	assert.Equal(t, got.Status, "approved")
	assert.NotNil(t, got.ApprovedBy)
	assert.Equal(t, *got.ApprovedBy, approverID)
	assert.NotNil(t, got.ApprovedAt)
	assert.NotNil(t, got.ReviewNotes)
	assert.Equal(t, *got.ReviewNotes, "looks fine")
	assert.True(t, got.UpdatedAt.After(ra.CreatedAt))

	// Reject a second acceptance on the same finding.
	ra2, err := env.stores.RiskAcceptance.Create(env.ctx, RiskAcceptanceCreate{
		FindingID: ids.findingID,
		UserID:    ids.userID,
		Rationale: "accepted for now",
		ExpiresAt: time.Now().AddDate(0, 1, 0),
		Status:    "pending",
	})
	assert.NoError(t, err)

	time.Sleep(10 * time.Millisecond)

	assert.NoError(t, env.stores.RiskAcceptance.Reject(env.ctx, ra2.ID, "not acceptable"))

	got2, err := env.stores.RiskAcceptance.GetByFindingID(env.ctx, ids.findingID)
	assert.NoError(t, err)
	assert.Equal(t, got2.ID, ra2.ID)
	assert.Equal(t, got2.Status, "rejected")
	assert.NotNil(t, got2.ReviewNotes)
	assert.Equal(t, *got2.ReviewNotes, "not acceptable")
	assert.True(t, got2.UpdatedAt.After(ra2.CreatedAt))
}

// ── Notifications ─────────────────────────────────────────────────────────────

func TestNotificationsCreateListMarkRead(t *testing.T) {
	env := newTestEnv(t)
	ids := seedBase(t, env.pool)

	entityType := "finding"
	entityID := ids.findingID
	notif, err := env.stores.Notifications.Create(env.ctx, NotificationCreate{
		UserID:     ids.userID,
		Title:      "New finding",
		Message:    "A high finding was detected",
		Type:       "finding_created",
		EntityType: &entityType,
		EntityID:   &entityID,
		AISummary:  "AI summary",
	})
	assert.NoError(t, err)
	assert.NotEqual(t, notif.ID, "")
	assert.Equal(t, notif.UserID, ids.userID)
	assert.Equal(t, notif.Title, "New finding")
	assert.Equal(t, notif.Message, "A high finding was detected")
	assert.Equal(t, notif.Type, "finding_created")
	assert.False(t, notif.Read)
	assert.Equal(t, notif.AISummary, "AI summary")
	assert.NotNil(t, notif.EntityType)
	assert.Equal(t, *notif.EntityType, "finding")
	assert.NotNil(t, notif.EntityID)
	assert.Equal(t, *notif.EntityID, ids.findingID)

	unread := false
	list, total, err := env.stores.Notifications.List(env.ctx, NotificationFilter{
		UserID: ids.userID,
		Read:   &unread,
		Page:   1,
		Limit:  10,
	})
	assert.NoError(t, err)
	assert.Equal(t, total, 1)
	assert.Equal(t, len(list), 1)
	assert.Equal(t, list[0].ID, notif.ID)

	assert.NoError(t, env.stores.Notifications.MarkAsRead(env.ctx, notif.ID, ids.userID))

	list, total, err = env.stores.Notifications.List(env.ctx, NotificationFilter{
		UserID: ids.userID,
		Read:   &unread,
		Page:   1,
		Limit:  10,
	})
	assert.NoError(t, err)
	assert.Equal(t, total, 0)
	assert.Equal(t, len(list), 0)

	count, err := env.stores.Notifications.GetUnreadCount(env.ctx, ids.userID)
	assert.NoError(t, err)
	assert.Equal(t, count, 0)

	// A different user cannot mark someone else's notification as read.
	err = env.stores.Notifications.MarkAsRead(env.ctx, notif.ID, uuid.NewString())
	assert.NotNil(t, err)
}

// ── Scan schedules ────────────────────────────────────────────────────────────

func TestSchedulesCreateList(t *testing.T) {
	env := newTestEnv(t)
	ids := seedBase(t, env.pool)

	// Project-scoped schedule with an individual scanner.
	s1, err := env.stores.Schedules.Create(env.ctx, ScanScheduleCreate{
		ProjectID: ids.projectID,
		Scanner:   "semgrep",
		CronExpr:  "0 9 * * 1",
	})
	assert.NoError(t, err)
	assert.NotEqual(t, s1.ID, "")
	assert.Equal(t, s1.ProjectID, ids.projectID)
	assert.Nil(t, s1.AppID)
	assert.Equal(t, s1.Scanner, "semgrep")
	assert.Nil(t, s1.ScannerType)
	assert.Equal(t, s1.CronExpr, "0 9 * * 1")
	assert.True(t, s1.Enabled)

	// App-scoped schedule: project_id NULL, scanner empty (scanner_type set).
	scannerType := "sast"
	s2, err := env.stores.Schedules.Create(env.ctx, ScanScheduleCreate{
		AppID:       &ids.appID,
		Scanner:     "",
		ScannerType: &scannerType,
		CronExpr:    "0 12 * * 3",
	})
	assert.NoError(t, err)
	assert.Equal(t, s2.ProjectID, "")
	assert.NotNil(t, s2.AppID)
	assert.Equal(t, *s2.AppID, ids.appID)
	assert.Equal(t, s2.Scanner, "")
	assert.NotNil(t, s2.ScannerType)
	assert.Equal(t, *s2.ScannerType, "sast")

	// ListByProject returns only the project-scoped schedule.
	byProject, err := env.stores.Schedules.ListByProject(env.ctx, datascope.Admin(), ids.projectID)
	assert.NoError(t, err)
	assert.Equal(t, len(byProject), 1)
	assert.Equal(t, byProject[0].ID, s1.ID)

	// ListEnabled (admin scope) returns both.
	enabled, err := env.stores.Schedules.ListEnabled(env.ctx, datascope.Admin())
	assert.NoError(t, err)
	assert.Equal(t, len(enabled), 2)
}

// ── API tokens ────────────────────────────────────────────────────────────────

func TestTokensCreateGetByPrefixRotate(t *testing.T) {
	env := newTestEnv(t)
	ids := seedBase(t, env.pool)

	tok, err := env.stores.Tokens.Create(env.ctx, TokenCreate{
		Name:      "ci-token",
		ProjectID: &ids.projectID,
		CreatedBy: ids.userID,
	}, "hash-v1", "hkp_aaaa1111")
	assert.NoError(t, err)
	assert.NotEqual(t, tok.ID, "")
	assert.Equal(t, tok.Name, "ci-token")
	assert.Equal(t, tok.Prefix, "hkp_aaaa1111")
	assert.NotNil(t, tok.ProjectID)
	assert.Equal(t, *tok.ProjectID, ids.projectID)
	assert.NotNil(t, tok.CreatedBy)
	assert.Equal(t, *tok.CreatedBy, ids.userID)

	got, err := env.stores.Tokens.GetByPrefix(env.ctx, "hkp_aaaa1111")
	assert.NoError(t, err)
	assert.NotNil(t, got)
	assert.Equal(t, got.Hash, "hash-v1")

	// Rotate replaces hash and prefix in place, preserving name/scope.
	rotated, err := env.stores.Tokens.Rotate(env.ctx, tok.ID, ids.userID, "hash-v2", "hkp_bbbb2222")
	assert.NoError(t, err)
	assert.Equal(t, rotated.Prefix, "hkp_bbbb2222")
	assert.Equal(t, rotated.Name, "ci-token")
	assert.NotNil(t, rotated.ProjectID)
	assert.Equal(t, *rotated.ProjectID, ids.projectID)

	got, err = env.stores.Tokens.GetByPrefix(env.ctx, "hkp_bbbb2222")
	assert.NoError(t, err)
	assert.NotNil(t, got)
	assert.Equal(t, got.Hash, "hash-v2")

	// The old prefix no longer resolves — the old secret is revoked.
	got, err = env.stores.Tokens.GetByPrefix(env.ctx, "hkp_aaaa1111")
	assert.NoError(t, err)
	assert.Nil(t, got)

	// Rotating a token owned by someone else fails.
	_, err = env.stores.Tokens.Rotate(env.ctx, tok.ID, uuid.NewString(), "hash-v3", "hkp_cccc3333")
	assert.ErrorIs(t, err, pgx.ErrNoRows)
}

// ── Webhooks ──────────────────────────────────────────────────────────────────

func TestWebhooksCreateListLogDelivery(t *testing.T) {
	env := newTestEnv(t)

	// webhooks is not truncated by testdb.Reset — use a unique label and
	// clean up so later tests see a stable list.
	label := "slack-" + uuid.NewString()
	wh, err := env.stores.Webhooks.Create(env.ctx, WebhookCreate{
		Label:        label,
		URL:          "https://hooks.example.com/slack",
		DeliveryType: "slack",
		Events:       []string{"finding.created", "scan.completed"},
	})
	assert.NoError(t, err)
	assert.NotEqual(t, wh.ID, "")
	assert.Equal(t, wh.Label, label)
	assert.Equal(t, wh.URL, "https://hooks.example.com/slack")
	assert.Equal(t, wh.DeliveryType, "slack")
	assert.True(t, wh.Enabled)
	assert.Equal(t, len(wh.Events), 2)
	assert.Equal(t, wh.Events[0], "finding.created")
	assert.Equal(t, wh.Events[1], "scan.completed")
	assert.Equal(t, wh.DeliveryCount, 0)
	assert.Equal(t, wh.ErrorCount, 0)

	t.Cleanup(func() {
		_ = env.stores.Webhooks.Delete(env.ctx, wh.ID)
	})

	list, err := env.stores.Webhooks.List(env.ctx)
	assert.NoError(t, err)
	found := false
	for _, w := range list {
		if w.ID == wh.ID {
			found = true
			assert.Equal(t, w.Label, label)
			assert.Equal(t, len(w.Events), 2)
		}
	}
	assert.True(t, found)

	statusCode := 200
	responseBody := "ok"
	assert.NoError(t, env.stores.Webhooks.LogDelivery(env.ctx, WebhookDeliveryInsert{
		WebhookID:    wh.ID,
		EventType:    "finding.created",
		Payload:      []byte(`{"event":"finding.created"}`),
		StatusCode:   &statusCode,
		ResponseBody: &responseBody,
	}))

	logs, err := env.stores.Webhooks.GetDeliveryLogs(env.ctx, wh.ID, 10)
	assert.NoError(t, err)
	assert.Equal(t, len(logs), 1)
	assert.Equal(t, logs[0].WebhookID, wh.ID)
	assert.Equal(t, logs[0].EventType, "finding.created")
	assert.Equal(t, string(logs[0].Payload), `{"event": "finding.created"}`)
	assert.NotNil(t, logs[0].StatusCode)
	assert.Equal(t, *logs[0].StatusCode, 200)
	assert.NotNil(t, logs[0].ResponseBody)
	assert.Equal(t, *logs[0].ResponseBody, "ok")
	assert.Nil(t, logs[0].ErrorMessage)
	assert.False(t, logs[0].CreatedAt.IsZero())
}

// ── Audit logs ────────────────────────────────────────────────────────────────

func TestAuditLogInsertList(t *testing.T) {
	env := newTestEnv(t)

	// audit_logs.user_id has NO foreign key — a user that does not exist in
	// the users table is accepted.
	ghostUserID := uuid.NewString()
	action := "test.audit." + uuid.NewString()
	entityID := uuid.NewString()

	assert.NoError(t, env.stores.Audit.Log(env.ctx, AuditLogEntry{
		UserID:     ghostUserID,
		UserEmail:  "ghost@test.local",
		Action:     action,
		EntityType: "finding",
		EntityID:   entityID,
		OldValue:   map[string]any{"status": "open"},
		NewValue:   map[string]any{"status": "closed"},
		IPAddress:  "192.168.1.1",
		UserAgent:  "curl/8.0",
	}))

	logs, total, err := env.stores.Audit.List(env.ctx, AuditFilter{
		Action: action,
		Page:   1,
		Limit:  50,
		Scope:  datascope.Admin(),
	})
	assert.NoError(t, err)
	assert.Equal(t, total, 1)
	assert.Equal(t, len(logs), 1)
	assert.Equal(t, logs[0].UserID, ghostUserID)
	assert.Equal(t, logs[0].UserEmail, "ghost@test.local")
	assert.Equal(t, logs[0].Action, action)
	assert.Equal(t, logs[0].EntityType, "finding")
	assert.Equal(t, logs[0].EntityID, entityID)
	oldVal, ok := logs[0].OldValue.(map[string]any)
	assert.True(t, ok)
	assert.Equal(t, oldVal["status"], "open")
	newVal, ok := logs[0].NewValue.(map[string]any)
	assert.True(t, ok)
	assert.Equal(t, newVal["status"], "closed")
	assert.Equal(t, logs[0].IPAddress, "192.168.1.1/32")
	assert.Equal(t, logs[0].UserAgent, "curl/8.0")
	assert.False(t, logs[0].CreatedAt.IsZero())

	// Filter by user_id.
	logs, total, err = env.stores.Audit.List(env.ctx, AuditFilter{
		UserID: ghostUserID,
		Page:   1,
		Limit:  50,
		Scope:  datascope.Admin(),
	})
	assert.NoError(t, err)
	assert.Equal(t, total, 1)
	assert.Equal(t, len(logs), 1)

	// Empty IP/UA are stored as NULL and read back as "".
	assert.NoError(t, env.stores.Audit.Log(env.ctx, AuditLogEntry{
		UserID:     ghostUserID,
		UserEmail:  "ghost@test.local",
		Action:     action,
		EntityType: "finding",
		EntityID:   uuid.NewString(),
	}))

	logs, total, err = env.stores.Audit.List(env.ctx, AuditFilter{
		Action: action,
		Page:   1,
		Limit:  50,
		Scope:  datascope.Admin(),
	})
	assert.NoError(t, err)
	assert.Equal(t, total, 2)
	assert.Equal(t, len(logs), 2)
	// Newest first.
	assert.Equal(t, logs[0].IPAddress, "")
	assert.Equal(t, logs[0].UserAgent, "")
}