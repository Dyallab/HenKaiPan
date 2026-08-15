//go:build integration

package db

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestApplyNonTransactionalConcurrently(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL not set; skipping integration test")
	}

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()

	conn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	defer conn.Release()

	// Clean slate
	if _, err := conn.Exec(ctx, `DROP TABLE IF EXISTS _mig_cc_test`); err != nil {
		t.Fatalf("drop: %v", err)
	}
	if _, err := conn.Exec(ctx, `CREATE TABLE _mig_cc_test (id int)`); err != nil {
		t.Fatalf("create: %v", err)
	}
	defer conn.Exec(context.Background(), `DROP TABLE IF EXISTS _mig_cc_test`)

	sql := `-- NO TRANSACTION
ALTER TABLE _mig_cc_test ADD COLUMN IF NOT EXISTS sso_provider TEXT;
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS _mig_cc_test_idx
    ON _mig_cc_test (sso_provider)
    WHERE sso_provider IS NOT NULL;`

	ver := fmt.Sprintf("TEST_%d", time.Now().UnixNano())
	if err := applyNonTransactional(ctx, conn, sql, ver); err != nil {
		t.Fatalf("applyNonTransactional failed: %v", err)
	}

	var count int
	if err := conn.QueryRow(ctx, `SELECT COUNT(*) FROM pg_indexes WHERE indexname = '_mig_cc_test_idx'`).Scan(&count); err != nil {
		t.Fatalf("verify index: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected index to exist, got count=%d", count)
	}
}
