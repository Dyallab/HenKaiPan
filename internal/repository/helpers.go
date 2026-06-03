package repository

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func EnsureSlice[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

// allowedDeleteTables is a whitelist of table names allowed in DeleteByID.
// This prevents SQL injection via dynamic table names.
var allowedDeleteTables = map[string]bool{
	"apps":            true,
	"projects":        true,
	"scan_schedules":  true,
	"teams":           true,
	"users":           true,
	"webhooks":        true,
}

func DeleteByID(ctx context.Context, db *pgxpool.Pool, table, id string) error {
	if !allowedDeleteTables[table] {
		return fmt.Errorf("delete %s: table not allowed", table)
	}
	tag, err := db.Exec(ctx, fmt.Sprintf("DELETE FROM %s WHERE id = $1", table), id)
	if err != nil {
		return fmt.Errorf("delete %s: %w", table, err)
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

const SeverityOrderSQL = `CASE f.severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END`