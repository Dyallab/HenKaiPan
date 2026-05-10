package repository

import (
	"context"
	"fmt"
	"time"

	"aspm/internal/models"

	"github.com/jackc/pgx/v5/pgxpool"
)

type scheduleRepo struct {
	db *pgxpool.Pool
}

const scheduleCols = "id, project_id, app_id, scanner, scanner_type, cron_expr, enabled, last_run, next_run, created_at"

func scanSchedule(s *models.ScanSchedule, row interface{ Scan(...interface{}) error }) error {
	return row.Scan(&s.ID, &s.ProjectID, &s.AppID, &s.Scanner, &s.ScannerType, &s.CronExpr, &s.Enabled, &s.LastRun, &s.NextRun, &s.CreatedAt)
}

func (r *scheduleRepo) ListByProject(ctx context.Context, projectID string) ([]models.ScanSchedule, error) {
	rows, err := r.db.Query(ctx, `
		SELECT `+scheduleCols+`
		FROM scan_schedules
		WHERE project_id = $1
		ORDER BY created_at DESC`, projectID)
	if err != nil {
		return nil, fmt.Errorf("list schedules by project: %w", err)
	}
	defer rows.Close()

	var out []models.ScanSchedule
	for rows.Next() {
		var s models.ScanSchedule
		if err := scanSchedule(&s, rows); err != nil {
			continue
		}
		out = append(out, s)
	}
	return EnsureSlice(out), nil
}

func (r *scheduleRepo) ListEnabled(ctx context.Context) ([]models.ScanSchedule, error) {
	rows, err := r.db.Query(ctx, `
		SELECT `+scheduleCols+`
		FROM scan_schedules
		WHERE enabled = TRUE
		ORDER BY next_run ASC NULLS FIRST`)
	if err != nil {
		return nil, fmt.Errorf("list enabled schedules: %w", err)
	}
	defer rows.Close()

	var out []models.ScanSchedule
	for rows.Next() {
		var s models.ScanSchedule
		if err := scanSchedule(&s, rows); err != nil {
			continue
		}
		out = append(out, s)
	}
	return EnsureSlice(out), nil
}

func (r *scheduleRepo) GetByID(ctx context.Context, id string) (*models.ScanSchedule, error) {
	var s models.ScanSchedule
	err := scanSchedule(&s, r.db.QueryRow(ctx, `
		SELECT `+scheduleCols+`
		FROM scan_schedules WHERE id = $1`, id))
	if err != nil {
		return nil, fmt.Errorf("get schedule: %w", err)
	}
	return &s, nil
}

func (r *scheduleRepo) Create(ctx context.Context, s ScanScheduleCreate) (*models.ScanSchedule, error) {
	var projectID *string
	if s.ProjectID != "" {
		projectID = &s.ProjectID
	}
	var out models.ScanSchedule
	err := scanSchedule(&out, r.db.QueryRow(ctx, `
		INSERT INTO scan_schedules (project_id, app_id, scanner, scanner_type, cron_expr)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING `+scheduleCols,
		projectID, s.AppID, s.Scanner, s.ScannerType, s.CronExpr))
	if err != nil {
		return nil, fmt.Errorf("create schedule: %w", err)
	}
	return &out, nil
}

func (r *scheduleRepo) Update(ctx context.Context, id string, upd ScanScheduleUpdate) (*models.ScanSchedule, error) {
	var out models.ScanSchedule
	query := `UPDATE scan_schedules SET `
	args := []interface{}{id}
	argIdx := 2
	var sets []string

	if upd.Scanner != nil {
		sets = append(sets, fmt.Sprintf("scanner = $%d", argIdx))
		args = append(args, *upd.Scanner)
		argIdx++
	}
	if upd.ScannerType != nil {
		sets = append(sets, fmt.Sprintf("scanner_type = $%d", argIdx))
		args = append(args, *upd.ScannerType)
		argIdx++
	}
	if upd.CronExpr != nil {
		sets = append(sets, fmt.Sprintf("cron_expr = $%d", argIdx))
		args = append(args, *upd.CronExpr)
		argIdx++
	}
	if upd.Enabled != nil {
		sets = append(sets, fmt.Sprintf("enabled = $%d", argIdx))
		args = append(args, *upd.Enabled)
		argIdx++
	}

	if len(sets) == 0 {
		return r.GetByID(ctx, id)
	}

	query += sets[0]
	for i := 1; i < len(sets); i++ {
		query += ", " + sets[i]
	}
	query += fmt.Sprintf(" WHERE id = $1 RETURNING "+scheduleCols)

	err := r.db.QueryRow(ctx, query, args...).
		Scan(&out.ID, &out.ProjectID, &out.Scanner, &out.ScannerType, &out.CronExpr, &out.Enabled, &out.LastRun, &out.NextRun, &out.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("update schedule: %w", err)
	}
	return &out, nil
}

func (r *scheduleRepo) Delete(ctx context.Context, id string) error {
	return DeleteByID(ctx, r.db, "scan_schedules", id)
}

func (r *scheduleRepo) ListDue(ctx context.Context) ([]models.ScanSchedule, error) {
	rows, err := r.db.Query(ctx, `
		SELECT `+scheduleCols+`
		FROM scan_schedules
		WHERE enabled = TRUE AND (next_run IS NULL OR next_run <= NOW())
		ORDER BY next_run ASC NULLS FIRST
		LIMIT 50`)
	if err != nil {
		return nil, fmt.Errorf("list due schedules: %w", err)
	}
	defer rows.Close()

	var out []models.ScanSchedule
	for rows.Next() {
		var s models.ScanSchedule
		if err := scanSchedule(&s, rows); err != nil {
			continue
		}
		out = append(out, s)
	}
	return EnsureSlice(out), nil
}

func (r *scheduleRepo) MarkRun(ctx context.Context, id string, nextRun *time.Time) error {
	_, err := r.db.Exec(ctx, `
		UPDATE scan_schedules
		SET last_run = NOW(), next_run = $2
		WHERE id = $1`, id, nextRun)
	return err
}
