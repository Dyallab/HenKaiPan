//go:build integration

package testdb

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"aspm/internal/assert"
)

// TestResetTruncatesSeedData inserts a full demo-data chain (team → user →
// app → project → scan → finding, plus a finding comment) and verifies
// Reset wipes it all, including FK dependents of the seed tables.
func TestResetTruncatesSeedData(t *testing.T) {
	pool := Connect(t)
	ctx := context.Background()

	teamID, userID := uuid.NewString(), uuid.NewString()
	appID, projectID := uuid.NewString(), uuid.NewString()
	scanID, findingID := uuid.NewString(), uuid.NewString()

	inserts := []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO teams (id, name) VALUES ($1, $2)`, []any{teamID, "test-team"}},
		{`INSERT INTO users (id, username, email, password_hash, role) VALUES ($1, $2, $3, $4, $5)`, []any{userID, "tester", "tester@test.local", "hash", "viewer"}},
		{`INSERT INTO team_members (team_id, user_id) VALUES ($1, $2)`, []any{teamID, userID}},
		{`INSERT INTO apps (id, name, team_id) VALUES ($1, $2, $3)`, []any{appID, "test-app", teamID}},
		{`INSERT INTO projects (id, name, app_id) VALUES ($1, $2, $3)`, []any{projectID, "test-project", appID}},
		{`INSERT INTO scans (id, project_id, scanner, status, target, scan_batch_id) VALUES ($1, $2, $3, $4, $5, gen_random_uuid())`, []any{scanID, projectID, "semgrep", "completed", "https://example.com/repo"}},
		{`INSERT INTO findings (id, scan_id, project_id, scanner, rule_id, title, severity, file_path, line_start, line_end, status, fingerprint) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`, []any{findingID, scanID, projectID, "semgrep", "rule-1", "Test finding", "high", "src/main.go", 1, 2, "open", "fp-1"}},
		{`INSERT INTO finding_comments (finding_id, user_id, content) VALUES ($1, $2, $3)`, []any{findingID, userID, "comment"}},
	}
	for _, ins := range inserts {
		if _, err := pool.Exec(ctx, ins.sql, ins.args...); err != nil {
			t.Fatalf("seed insert: %v", err)
		}
	}

	Reset(t, pool)

	assertCount(t, pool, "findings", 0)
	assertCount(t, pool, "finding_comments", 0)
	assertCount(t, pool, "scans", 0)
	assertCount(t, pool, "projects", 0)
}

// TestResetRestoresSingletons deletes the singleton rows (as a test for the
// settings/jira repos might) and verifies Reset re-inserts them.
func TestResetRestoresSingletons(t *testing.T) {
	pool := Connect(t)
	ctx := context.Background()

	if _, err := pool.Exec(ctx, `DELETE FROM notification_settings`); err != nil {
		t.Fatalf("delete notification_settings: %v", err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM jira_integrations`); err != nil {
		t.Fatalf("delete jira_integrations: %v", err)
	}

	Reset(t, pool)

	assertCount(t, pool, "notification_settings", 1)
	assertCount(t, pool, "jira_integrations", 1)
}

func assertCount(t *testing.T, pool *pgxpool.Pool, table string, want int) {
	t.Helper()
	var got int
	if err := pool.QueryRow(context.Background(), "SELECT COUNT(*) FROM "+table).Scan(&got); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	assert.Equal(t, got, want)
}