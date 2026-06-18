package repository

import (
	"context"
	"fmt"
	"time"

	"aspm/internal/datascope"
	"aspm/internal/models"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type scheduleRepo struct {
	db *pgxpool.Pool
}

const scheduleCols = "id, project_id, app_id, scanner, scanner_type, cron_expr, enabled, last_run, next_run, created_at"

func scanSchedule(s *models.ScanSchedule, row interface{ Scan(...interface{}) error }) error {
	return row.Scan(&s.ID, &s.ProjectID, &s.AppID, &s.Scanner, &s.ScannerType, &s.CronExpr, &s.Enabled, &s.LastRun, &s.NextRun, &s.CreatedAt)
}

func (r *scheduleRepo) ListByProject(ctx context.Context, scope datascope.Scope, projectID string) ([]models.ScanSchedule, error) {
	rows, err := r.db.Query(ctx, `
		SELECT `+scheduleCols+`
		FROM scan_schedules
		WHERE ($1::uuid IS NULL OR EXISTS (
			SELECT 1 FROM team_members tm
			JOIN apps a ON a.team_id = tm.team_id
			JOIN projects p ON p.app_id = a.id
			WHERE tm.user_id = $1 AND p.id = scan_schedules.project_id
		))
		AND project_id = $2
		ORDER BY created_at DESC`, scope.UserID, projectID)
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

func (r *scheduleRepo) ListEnabled(ctx context.Context, scope datascope.Scope) ([]models.ScanSchedule, error) {
	rows, err := r.db.Query(ctx, `
		SELECT `+scheduleCols+`
		FROM scan_schedules
		WHERE ($1::uuid IS NULL OR EXISTS (
			SELECT 1 FROM team_members tm
			JOIN apps a ON a.team_id = tm.team_id
			JOIN projects p ON p.app_id = a.id
			WHERE tm.user_id = $1 AND (p.id = scan_schedules.project_id OR a.id = scan_schedules.app_id)
		))
		AND enabled = TRUE
		ORDER BY next_run ASC NULLS FIRST`, scope.UserID)
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
		VALUES (@project_id, @app_id, @scanner, @scanner_type, @cron_expr)
		RETURNING `+scheduleCols,
		pgx.NamedArgs{
			"project_id":   projectID,
			"app_id":       s.AppID,
			"scanner":      s.Scanner,
			"scanner_type": s.ScannerType,
			"cron_expr":    s.CronExpr,
		}))
	if err != nil {
		return nil, fmt.Errorf("create schedule: %w", err)
	}
	return &out, nil
}

func (r *scheduleRepo) Update(ctx context.Context, id string, upd ScanScheduleUpdate) (*models.ScanSchedule, error) {
	var out models.ScanSchedule
	args := pgx.NamedArgs{"id": id}
	var sets []string

	if upd.Scanner != nil {
		sets = append(sets, "scanner = @scanner")
		args["scanner"] = *upd.Scanner
	}
	if upd.ScannerType != nil {
		sets = append(sets, "scanner_type = @scanner_type")
		args["scanner_type"] = *upd.ScannerType
	}
	if upd.CronExpr != nil {
		sets = append(sets, "cron_expr = @cron_expr")
		args["cron_expr"] = *upd.CronExpr
	}
	if upd.Enabled != nil {
		sets = append(sets, "enabled = @enabled")
		args["enabled"] = *upd.Enabled
	}

	if len(sets) == 0 {
		return r.GetByID(ctx, id)
	}

	query := `UPDATE scan_schedules SET ` + sets[0]
	for i := 1; i < len(sets); i++ {
		query += ", " + sets[i]
	}
	query += ` WHERE id = @id RETURNING ` + scheduleCols

	err := r.db.QueryRow(ctx, query, args).
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
		SET last_run = NOW(), next_run = @next_run
		WHERE id = @id`,
		pgx.NamedArgs{
			"id":       id,
			"next_run": nextRun,
		})
	return err
}
