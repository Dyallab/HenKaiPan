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

func RunMigrations(ctx context.Context, pool *pgxpool.Pool) error {
	slog.Info("running database migrations")

	if err := ensureSchemaTable(ctx, pool); err != nil {
		return fmt.Errorf("ensure schema table: %w", err)
	}

	applied, err := getAppliedMigrations(ctx, pool)
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

		tx, err := pool.Begin(ctx)
		if err != nil {
			return fmt.Errorf("begin tx for %s: %w", f, err)
		}

		if _, err := tx.Exec(ctx, string(data)); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("exec migration %s: %w", f, err)
		}

		if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations (version) VALUES ($1)`, ver); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("record migration %s: %w", f, err)
		}

		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("commit migration %s: %w", f, err)
		}

		slog.Info("migration applied", "version", ver)
	}

	slog.Info("migrations complete", "applied", len(pending))
	return nil
}

func ensureSchemaTable(ctx context.Context, pool *pgxpool.Pool) error {
	_, err := pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version TEXT PRIMARY KEY,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)
	`)
	return err
}

func getAppliedMigrations(ctx context.Context, pool *pgxpool.Pool) (map[string]bool, error) {
	rows, err := pool.Query(ctx, `SELECT version FROM schema_migrations`)
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