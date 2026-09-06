// Package testdb provides shared helpers for integration tests that need a
// real Postgres database (build tag: integration).
//
// Connect opens a pool against TEST_DATABASE_URL (falling back to
// DATABASE_URL), runs migrations once per process, and registers pool
// cleanup on the test. Reset wipes the seed tables and restores the
// singleton rows so each test starts from a known state.
package testdb

import (
	"context"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"aspm/internal/db"
)

var (
	migrateOnce sync.Once
	migrateErr  error
)

// Connect opens a pgx pool for integration tests.
//
// It reads TEST_DATABASE_URL first, falling back to DATABASE_URL, and skips
// the test when neither is set. It deliberately does NOT use db.Connect:
// that helper calls os.Exit on failure, which would abort the whole test
// binary instead of skipping.
//
// Migrations run once per test binary via db.RunMigrations, which is
// idempotent (schema_migrations tracks applied versions) and guarded by an
// advisory lock, so concurrent Connect calls from parallel tests are safe.
func Connect(t testing.TB) *pgxpool.Pool {
	t.Helper()

	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		dsn = os.Getenv("DATABASE_URL")
	}
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL/DATABASE_URL not set; skipping integration test")
	}

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("testdb: connect: %v", err)
	}
	t.Cleanup(pool.Close)

	if err := pool.Ping(ctx); err != nil {
		t.Fatalf("testdb: ping: %v", err)
	}

	migrateOnce.Do(func() {
		migrateErr = db.RunMigrations(ctx, pool)
	})
	if migrateErr != nil {
		t.Fatalf("testdb: migrations: %v", migrateErr)
	}

	return pool
}

// seedTables lists the tables Reset truncates, in FK-safe order (children
// before parents). It covers the demo-data tables seeded by
// scripts/seed-demo.sql (teams, users, team_members, apps, projects, scans,
// findings) plus their FK dependents, so TRUNCATE never trips over rows left
// behind by earlier tests.
//
// notification_settings and jira_integrations are deliberately excluded:
// they are singletons (single row, PRIMARY KEY singleton = TRUE) whose
// baseline row is configuration tests rely on. Reset restores them instead
// of truncating them — see Reset.
//
// The names are compile-time constants (a whitelist), never user input.
var seedTables = []string{
	// findings and its dependents
	"jira_issue_links",       // findings(id)
	"agent_analyses",         // findings(id)
	"finding_correlations",   // findings(id)
	"finding_comments",       // findings(id), users(id)
	"risk_acceptances",       // findings(id), users(id)
	"findings",               // scans(id), projects(id)
	// scans
	"scans",                  // projects(id)
	// projects and its dependents
	"vulnerabilities",        // projects(id)
	"project_dependencies",   // projects(id)
	"project_inventory_hits", // projects(id)
	"scan_schedules",         // projects(id), apps(id)
	"api_tokens",             // projects(id), users(id)
	"projects",               // apps(id)
	// apps
	"apps",                   // teams(id)
	// teams / users and their dependents
	"team_members",           // teams(id), users(id)
	"user_notifications",     // users(id)
	"teams",
	"users",
}

// Reset truncates the seed tables and restores the singleton rows, giving
// each test a clean slate.
//
// Caveat: notification_settings and jira_integrations are singletons — a
// single row keyed by singleton = TRUE that migrations seed and repository
// code reads as baseline configuration. Reset never truncates them (tests
// depend on the row existing), but if a test deleted the row, Reset
// re-inserts it with INSERT ... ON CONFLICT (singleton) DO NOTHING.
func Reset(t testing.TB, pool *pgxpool.Pool) {
	t.Helper()

	ctx := context.Background()
	conn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("testdb: reset: acquire: %v", err)
	}
	defer conn.Release()

	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatalf("testdb: reset: begin: %v", err)
	}
	defer tx.Rollback(ctx) // no-op after commit

	// All referencing tables must appear in the same TRUNCATE command —
	// PostgreSQL rejects truncating a table whose FK children are not
	// truncated alongside it, even within the same transaction.
	if _, err := tx.Exec(ctx, "TRUNCATE TABLE "+strings.Join(seedTables, ", ")); err != nil {
		t.Fatalf("testdb: reset: truncate: %v", err)
	}

	// Restore singleton rows (no-op when they survived the test).
	if _, err := tx.Exec(ctx, `INSERT INTO notification_settings (singleton) VALUES (TRUE) ON CONFLICT (singleton) DO NOTHING`); err != nil {
		t.Fatalf("testdb: reset: restore notification_settings: %v", err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO jira_integrations (singleton) VALUES (TRUE) ON CONFLICT (singleton) DO NOTHING`); err != nil {
		t.Fatalf("testdb: reset: restore jira_integrations: %v", err)
	}

	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("testdb: reset: commit: %v", err)
	}
}