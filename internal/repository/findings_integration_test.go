//go:build integration

package repository

// Integration tests for the scan + finding store round-trip and the
// per-project fingerprint dedup contract.
//
// Requires a reachable Postgres (TEST_DATABASE_URL, falling back to
// DATABASE_URL — see internal/testdb). Each test connects and resets the
// seed tables so it starts from a known state.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"testing"

	"aspm/internal/assert"
	"aspm/internal/models"
	"aspm/internal/testdb"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// findingsTestFingerprint mirrors the production fingerprint algorithm
// (internal/tasks/scan_run.go computeFingerprint): hex(sha256("scanner:rule_id:file_path:line_start")).
func findingsTestFingerprint(scanner, ruleID, filePath string, lineStart int) string {
	h := sha256.Sum256([]byte(scanner + ":" + ruleID + ":" + filePath + ":" + strconv.Itoa(lineStart)))
	return hex.EncodeToString(h[:])
}

func findingsTestStrPtr(s string) *string { return &s }

func findingsTestProject(t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()
	var id string
	err := pool.QueryRow(context.Background(),
		`INSERT INTO projects (name) VALUES ($1) RETURNING id`,
		"findings-test-project-"+uuid.NewString()[:8]).Scan(&id)
	if err != nil {
		t.Fatalf("create test project: %v", err)
	}
	return id
}

func findingsTestUser(t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()
	var id string
	err := pool.QueryRow(context.Background(),
		`INSERT INTO users (username, email, password_hash, role) VALUES ($1, $2, $3, 'viewer') RETURNING id`,
		"findings-test-user", "findings-test@example.com", "not-a-real-hash").Scan(&id)
	if err != nil {
		t.Fatalf("create test user: %v", err)
	}
	return id
}

func findingsTestScan(t *testing.T, stores Stores, projectID string) string {
	t.Helper()
	id, err := stores.Scans.Insert(context.Background(),
		"https://github.com/example/repo.git", "semgrep", uuid.NewString(), &projectID)
	if err != nil {
		t.Fatalf("insert scan: %v", err)
	}
	return id
}

func findingsTestInsert(t *testing.T, stores Stores, scanID, projectID, fingerprint, severity string) string {
	t.Helper()
	id, err := stores.Findings.Insert(context.Background(), FindingInsert{
		ScanID:      scanID,
		Scanner:     "semgrep",
		RuleID:      "test-rule",
		Title:       "Test finding",
		Description: "integration test finding",
		Severity:    severity,
		FilePath:    "src/main.go",
		LineStart:   10,
		LineEnd:     12,
		ProjectID:   projectID,
		Fingerprint: fingerprint,
	})
	if err != nil {
		t.Fatalf("insert finding: %v", err)
	}
	return id
}

func TestScanRepository_InsertPersistsBatchIDAndPendingStatus(t *testing.T) {
	ctx := context.Background()
	pool := testdb.Connect(t)
	testdb.Reset(t, pool)
	stores := NewPostgresStores(pool, "")
	projectID := findingsTestProject(t, pool)

	batchID := uuid.NewString()
	scanID, err := stores.Scans.Insert(ctx, "https://github.com/example/repo.git", "semgrep", batchID, &projectID)
	assert.NoError(t, err)
	assert.NotEqual(t, scanID, "")

	scan, err := stores.Scans.Get(ctx, scanID)
	assert.NoError(t, err)
	assert.NotNil(t, scan)
	assert.Equal(t, scan.Status, models.StatusPending)
	assert.Equal(t, scan.ProjectID, &projectID)

	var persistedBatchID string
	err = pool.QueryRow(ctx, `SELECT scan_batch_id FROM scans WHERE id = $1`, scanID).Scan(&persistedBatchID)
	assert.NoError(t, err)
	assert.Equal(t, persistedBatchID, batchID)
}

func TestFindingRepository_DedupSameFingerprintSameProject(t *testing.T) {
	ctx := context.Background()
	pool := testdb.Connect(t)
	testdb.Reset(t, pool)
	stores := NewPostgresStores(pool, "")
	projectID := findingsTestProject(t, pool)
	scanID := findingsTestScan(t, stores, projectID)
	fp := findingsTestFingerprint("semgrep", "rule-dedup", "src/main.go", 10)

	firstID := findingsTestInsert(t, stores, scanID, projectID, fp, "high")
	assert.NotEqual(t, firstID, "")

	// Second insert with the same fingerprint + project must be deduped:
	// Insert returns "" (no row) and the row count stays at 1.
	secondID, err := stores.Findings.Insert(ctx, FindingInsert{
		ScanID:      scanID,
		Scanner:     "semgrep",
		RuleID:      "rule-dedup",
		Title:       "Test finding",
		Description: "duplicate",
		Severity:    "high",
		FilePath:    "src/main.go",
		LineStart:   10,
		LineEnd:     12,
		ProjectID:   projectID,
		Fingerprint: fp,
	})
	assert.NoError(t, err)
	assert.Equal(t, secondID, "")

	var count int
	err = pool.QueryRow(ctx, `SELECT COUNT(*) FROM findings WHERE project_id = $1`, projectID).Scan(&count)
	assert.NoError(t, err)
	assert.Equal(t, count, 1)

	_, total, err := stores.Findings.List(ctx, FindingFilter{Page: 1, Limit: 50})
	assert.NoError(t, err)
	assert.Equal(t, total, 1)
}

func TestFindingRepository_SameFingerprintDifferentProjects(t *testing.T) {
	ctx := context.Background()
	pool := testdb.Connect(t)
	testdb.Reset(t, pool)
	stores := NewPostgresStores(pool, "")
	projectA := findingsTestProject(t, pool)
	projectB := findingsTestProject(t, pool)
	scanA := findingsTestScan(t, stores, projectA)
	scanB := findingsTestScan(t, stores, projectB)
	fp := findingsTestFingerprint("semgrep", "rule-cross", "src/main.go", 10)

	// The partial unique index only dedups within a project, so the same
	// fingerprint in a different project must be stored as its own row.
	idA := findingsTestInsert(t, stores, scanA, projectA, fp, "high")
	idB := findingsTestInsert(t, stores, scanB, projectB, fp, "high")
	assert.NotEqual(t, idA, "")
	assert.NotEqual(t, idB, "")
	assert.NotEqual(t, idA, idB)

	var count int
	err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM findings`).Scan(&count)
	assert.NoError(t, err)
	assert.Equal(t, count, 2)
}

func TestFindingRepository_ListFilters(t *testing.T) {
	ctx := context.Background()
	pool := testdb.Connect(t)
	testdb.Reset(t, pool)
	stores := NewPostgresStores(pool, "")

	projectA := findingsTestProject(t, pool)
	projectB := findingsTestProject(t, pool)
	scanA := findingsTestScan(t, stores, projectA)
	scanB := findingsTestScan(t, stores, projectB)

	// project A: critical/open + medium/in_review
	idA1 := findingsTestInsert(t, stores, scanA, projectA,
		findingsTestFingerprint("semgrep", "rule-a1", "src/a.go", 10), "critical")
	idA2 := findingsTestInsert(t, stores, scanA, projectA,
		findingsTestFingerprint("semgrep", "rule-a2", "src/a.go", 20), "medium")
	// project B: high/fixed
	idB1 := findingsTestInsert(t, stores, scanB, projectB,
		findingsTestFingerprint("semgrep", "rule-b1", "src/b.go", 30), "high")

	_, err := stores.Findings.Update(ctx, idA2, FindingUpdate{Status: findingsTestStrPtr("in_review")})
	assert.NoError(t, err)
	_, err = stores.Findings.Update(ctx, idB1, FindingUpdate{Status: findingsTestStrPtr("fixed")})
	assert.NoError(t, err)

	// Unfiltered list returns findings from every project.
	all, total, err := stores.Findings.List(ctx, FindingFilter{Page: 1, Limit: 50})
	assert.NoError(t, err)
	assert.Equal(t, total, 3)
	assert.Equal(t, len(all), 3)

	// Severity filter.
	crit, total, err := stores.Findings.List(ctx, FindingFilter{Severities: []string{"critical"}, Page: 1, Limit: 50})
	assert.NoError(t, err)
	assert.Equal(t, total, 1)
	assert.Equal(t, crit[0].ID, idA1)

	// Status filter.
	open, total, err := stores.Findings.List(ctx, FindingFilter{Status: "open", Page: 1, Limit: 50})
	assert.NoError(t, err)
	assert.Equal(t, total, 1)
	assert.Equal(t, open[0].ID, idA1)

	// Scanner filter.
	semgrep, total, err := stores.Findings.List(ctx, FindingFilter{Scanner: "semgrep", Page: 1, Limit: 50})
	assert.NoError(t, err)
	assert.Equal(t, total, 3)
	assert.Equal(t, len(semgrep), 3)
}

func TestFindingRepository_UpdateStatusAndResolvedAt(t *testing.T) {
	ctx := context.Background()
	pool := testdb.Connect(t)
	testdb.Reset(t, pool)
	stores := NewPostgresStores(pool, "")
	projectID := findingsTestProject(t, pool)
	scanID := findingsTestScan(t, stores, projectID)
	fp := findingsTestFingerprint("semgrep", "rule-upd", "src/main.go", 10)
	findingID := findingsTestInsert(t, stores, scanID, projectID, fp, "high")

	f, err := stores.Findings.GetByID(ctx, findingID)
	assert.NoError(t, err)
	assert.Equal(t, f.Status, models.FindingStatusOpen)
	assert.Nil(t, f.ResolvedAt)

	// Marking fixed stamps resolved_at.
	updated, err := stores.Findings.Update(ctx, findingID, FindingUpdate{Status: findingsTestStrPtr("fixed")})
	assert.NoError(t, err)
	assert.Equal(t, updated.Status, models.FindingStatusFixed)
	assert.NotNil(t, updated.ResolvedAt)

	// Reopening clears resolved_at.
	updated, err = stores.Findings.Update(ctx, findingID, FindingUpdate{Status: findingsTestStrPtr("open")})
	assert.NoError(t, err)
	assert.Equal(t, updated.Status, models.FindingStatusOpen)
	assert.Nil(t, updated.ResolvedAt)
}

func TestFindingRepository_ToggleFalsePositive(t *testing.T) {
	ctx := context.Background()
	pool := testdb.Connect(t)
	testdb.Reset(t, pool)
	stores := NewPostgresStores(pool, "")
	projectID := findingsTestProject(t, pool)
	scanID := findingsTestScan(t, stores, projectID)
	fp := findingsTestFingerprint("semgrep", "rule-fp", "src/main.go", 10)
	findingID := findingsTestInsert(t, stores, scanID, projectID, fp, "low")

	f, err := stores.Findings.GetByID(ctx, findingID)
	assert.NoError(t, err)
	assert.False(t, f.FalsePositive)

	fpTrue := true
	updated, err := stores.Findings.Update(ctx, findingID, FindingUpdate{FalsePositive: &fpTrue})
	assert.NoError(t, err)
	assert.True(t, updated.FalsePositive)

	fpFalse := false
	updated, err = stores.Findings.Update(ctx, findingID, FindingUpdate{FalsePositive: &fpFalse})
	assert.NoError(t, err)
	assert.False(t, updated.FalsePositive)
}

func TestFindingRepository_CreateCommentIncrementsCount(t *testing.T) {
	ctx := context.Background()
	pool := testdb.Connect(t)
	testdb.Reset(t, pool)
	stores := NewPostgresStores(pool, "")
	projectID := findingsTestProject(t, pool)
	scanID := findingsTestScan(t, stores, projectID)
	userID := findingsTestUser(t, pool)
	fp := findingsTestFingerprint("semgrep", "rule-comment", "src/main.go", 10)
	findingID := findingsTestInsert(t, stores, scanID, projectID, fp, "medium")

	commentCount := func() int {
		var n int
		err := pool.QueryRow(ctx, `SELECT comment_count FROM findings WHERE id = $1`, findingID).Scan(&n)
		assert.NoError(t, err)
		return n
	}
	assert.Equal(t, commentCount(), 0)

	_, err := stores.Apps.CreateFindingComment(ctx, CommentCreate{
		FindingID: findingID,
		UserID:    userID,
		Content:   "first comment",
	})
	assert.NoError(t, err)
	assert.Equal(t, commentCount(), 1)

	_, err = stores.Apps.CreateFindingComment(ctx, CommentCreate{
		FindingID: findingID,
		UserID:    userID,
		Content:   "second comment",
	})
	assert.NoError(t, err)
	assert.Equal(t, commentCount(), 2)
}