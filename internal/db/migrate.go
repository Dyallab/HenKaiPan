package db

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"log/slog"
	"sort"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

const migrationDir = "migrations"

// noTxMarker must be the first line of a migration that needs to run outside
// a transaction (for example CREATE INDEX CONCURRENTLY). Such migrations must
// be written to be idempotent because a partial run cannot be rolled back.
const noTxMarker = "-- NO TRANSACTION"

func RunMigrations(ctx context.Context, pool *pgxpool.Pool) error {
	slog.Info("running database migrations")

	// Acquire a dedicated connection for the entire migration run
	// This ensures the advisory lock and all migration queries use the same session
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("acquire connection: %w", err)
	}
	defer conn.Release()

	// Acquire advisory lock to prevent concurrent migration runs
	// from api and worker containers starting simultaneously
	const migrationLockID int64 = 2024010100
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock($1)`, migrationLockID); err != nil {
		return fmt.Errorf("acquire migration advisory lock: %w", err)
	}
	defer conn.Exec(context.Background(), `SELECT pg_advisory_unlock($1)`, migrationLockID)

	if err := ensureSchemaTableWithConn(ctx, conn); err != nil {
		return fmt.Errorf("ensure schema table: %w", err)
	}

	applied, err := getAppliedMigrationsWithConn(ctx, conn)
	if err != nil {
		return fmt.Errorf("get applied migrations: %w", err)
	}

	files, err := fs.Glob(migrationFS, migrationDir+"/*.sql")
	if err != nil {
		return fmt.Errorf("glob migrations: %w", err)
	}
	sort.Strings(files)

	var pending []string
	for _, f := range files {
		ver := versionFromPath(f)
		if _, ok := applied[ver]; !ok {
			pending = append(pending, f)
		}
	}

	if len(pending) == 0 {
		slog.Info("no pending migrations")
		return nil
	}

	for _, f := range pending {
		data, err := migrationFS.ReadFile(f)
		if err != nil {
			return fmt.Errorf("read migration %s: %w", f, err)
		}

		ver := versionFromPath(f)
		slog.Info("applying migration", "file", f, "version", ver)

		if isNonTransactional(data) {
			if err := applyNonTransactional(ctx, conn, string(data), ver); err != nil {
				return fmt.Errorf("exec migration %s: %w", f, err)
			}
		} else {
			if err := applyTransactional(ctx, conn, string(data), ver); err != nil {
				return fmt.Errorf("exec migration %s: %w", f, err)
			}
		}

		slog.Info("migration applied", "version", ver)
	}

	slog.Info("migrations complete", "applied", len(pending))
	return nil
}

func isNonTransactional(data []byte) bool {
	s := strings.TrimSpace(string(data))
	return strings.HasPrefix(s, noTxMarker)
}

func applyTransactional(ctx context.Context, conn *pgxpool.Conn, sql, ver string) error {
	tx, err := conn.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	if _, err := tx.Exec(ctx, sql); err != nil {
		_ = tx.Rollback(ctx)
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations (version) VALUES ($1)`, ver); err != nil {
		_ = tx.Rollback(ctx)
		return fmt.Errorf("record migration: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	return nil
}

func applyNonTransactional(ctx context.Context, conn *pgxpool.Conn, sql, ver string) error {
	if _, err := conn.Exec(ctx, sql); err != nil {
		return err
	}
	if _, err := conn.Exec(ctx, `INSERT INTO schema_migrations (version) VALUES ($1)`, ver); err != nil {
		return fmt.Errorf("record migration: %w", err)
	}
	return nil
}

func ensureSchemaTableWithConn(ctx context.Context, conn *pgxpool.Conn) error {
	_, err := conn.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version TEXT PRIMARY KEY,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)
	`)
	return err
}

func getAppliedMigrationsWithConn(ctx context.Context, conn *pgxpool.Conn) (map[string]bool, error) {
	rows, err := conn.Query(ctx, `SELECT version FROM schema_migrations`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	applied := make(map[string]bool)
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		applied[v] = true
	}
	return applied, rows.Err()
}

func versionFromPath(p string) string {
	name := p[strings.LastIndex(p, "/")+1:]
	dash := strings.Index(name, "_")
	if dash == -1 {
		return name
	}
	num, err := strconv.Atoi(name[:dash])
	if err != nil {
		return name[:dash]
	}
	return fmt.Sprintf("%03d", num)
}
