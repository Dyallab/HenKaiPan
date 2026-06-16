package repository

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

type usageRepo struct{ db *pgxpool.Pool }

func (r *usageRepo) IncrementAIScan(ctx context.Context, monthKey string, limit int) (bool, error) {
	if limit < 0 {
		return true, nil
	}
	if limit == 0 {
		return false, nil
	}
	res, err := r.db.Exec(ctx, `
		INSERT INTO usage_counters (key, value) VALUES ($1, 1)
		ON CONFLICT (key) DO UPDATE SET
			value = CASE WHEN usage_counters.value < $2 THEN usage_counters.value + 1
			             ELSE usage_counters.value END,
			updated_at = NOW()
		WHERE usage_counters.value < $2`, monthKey, limit)
	if err != nil {
		return false, fmt.Errorf("increment ai scan: %w", err)
	}
	return res.RowsAffected() > 0, nil
}

func (r *usageRepo) GetAIScanCount(ctx context.Context, monthKey string) (int, error) {
	var n int
	err := r.db.QueryRow(ctx,
		`SELECT COALESCE(value, 0) FROM usage_counters WHERE key = $1`, monthKey,
	).Scan(&n)
	if err != nil {
		if err.Error() == "no rows in result set" {
			return 0, nil
		}
		return 0, fmt.Errorf("get ai scan count: %w", err)
	}
	return n, nil
}
