package repository

import (
	"context"
	"fmt"

	"aspm/internal/models"

	"github.com/jackc/pgx/v5/pgxpool"
)

type scanRepo struct{ db *pgxpool.Pool }

func (r *scanRepo) List(ctx context.Context, page, limit int) ([]models.Scan, int, error) {
	if page < 1 {
		page = 1
	}
	if limit < 1 || limit > 100 {
		limit = 20
	}
	offset := (page - 1) * limit

	rows, err := r.db.Query(ctx, `
		SELECT s.id, s.repo_id, s.scanner, s.status, s.target,
		       s.started_at, s.completed_at, s.created_at, s.error,
		       COUNT(f.id) as finding_count
		FROM scans s
		LEFT JOIN findings f ON f.scan_id = s.id
		GROUP BY s.id
		ORDER BY s.created_at DESC
		LIMIT $1 OFFSET $2`, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("scans list: %w", err)
	}
	defer rows.Close()

	var scans []models.Scan
	for rows.Next() {
		var s models.Scan
		if err := rows.Scan(&s.ID, &s.RepoID, &s.Scanner, &s.Status, &s.Target,
			&s.StartedAt, &s.CompletedAt, &s.CreatedAt, &s.Error, &s.FindingCount); err != nil {
			continue
		}
		scans = append(scans, s)
	}
	if scans == nil {
		scans = []models.Scan{}
	}

	var total int
	r.db.QueryRow(ctx, `SELECT COUNT(*) FROM scans`).Scan(&total)

	return scans, total, nil
}

func (r *scanRepo) Get(ctx context.Context, id string) (*models.Scan, error) {
	var s models.Scan
	err := r.db.QueryRow(ctx, `
		SELECT s.id, s.repo_id, s.scanner, s.status, s.target,
		       s.started_at, s.completed_at, s.created_at, s.error,
		       s.container_log, COUNT(f.id)
		FROM scans s
		LEFT JOIN findings f ON f.scan_id = s.id
		WHERE s.id = $1
		GROUP BY s.id`, id,
	).Scan(&s.ID, &s.RepoID, &s.Scanner, &s.Status, &s.Target,
		&s.StartedAt, &s.CompletedAt, &s.CreatedAt, &s.Error,
		&s.ContainerLog, &s.FindingCount)
	if err != nil {
		return nil, err
	}
	return &s, nil
}

func (r *scanRepo) Insert(ctx context.Context, target, scanner string, repoID *string) (string, error) {
	var id string
	err := r.db.QueryRow(ctx,
		`INSERT INTO scans (target, scanner, status, repo_id) VALUES ($1, $2, 'pending', $3) RETURNING id`,
		target, scanner, repoID,
	).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("insert scan: %w", err)
	}
	return id, nil
}

func (r *scanRepo) FindRepoIDByTarget(ctx context.Context, target string) (*string, error) {
	var id string
	err := r.db.QueryRow(ctx, `SELECT id FROM repos WHERE url = $1`, target).Scan(&id)
	if err != nil {
		return nil, nil // not found is not an error
	}
	return &id, nil
}

func (r *scanRepo) MarkRunning(ctx context.Context, scanID string) error {
	_, err := r.db.Exec(ctx,
		`UPDATE scans SET status='running', started_at=NOW() WHERE id=$1`, scanID)
	if err != nil {
		return fmt.Errorf("mark running: %w", err)
	}
	return nil
}

func (r *scanRepo) MarkCompleted(ctx context.Context, scanID, containerLog string, exitErr *string) error {
	_, err := r.db.Exec(ctx,
		`UPDATE scans SET status='completed', completed_at=NOW(), container_log=$1 WHERE id=$2`,
		containerLog, scanID)
	if err != nil {
		return fmt.Errorf("mark completed: %w", err)
	}
	if exitErr != nil && *exitErr != "" {
		r.db.Exec(ctx, `UPDATE scans SET error=$1 WHERE id=$2`, *exitErr, scanID)
	}
	return nil
}

func (r *scanRepo) MarkFailed(ctx context.Context, scanID, errMsg, containerLog string) error {
	_, err := r.db.Exec(ctx,
		`UPDATE scans SET status='failed', completed_at=NOW(), error=$1, container_log=$2 WHERE id=$3`,
		errMsg, containerLog, scanID)
	if err != nil {
		return fmt.Errorf("mark failed: %w", err)
	}
	return nil
}

func (r *scanRepo) RecoverStuck(ctx context.Context) (int64, error) {
	tag, err := r.db.Exec(ctx,
		`UPDATE scans SET status='failed', error='worker restarted', completed_at=NOW() WHERE status='running'`)
	if err != nil {
		return 0, fmt.Errorf("recover stuck: %w", err)
	}
	return tag.RowsAffected(), nil
}
