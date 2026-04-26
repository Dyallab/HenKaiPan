package repository

import (
	"context"
	"fmt"

	"aspm/internal/models"
)

func (r *appRepo) ListProjects(ctx context.Context, appID string) ([]models.Project, error) {
	rows, err := r.db.Query(ctx, `
		SELECT p.id, p.name, p.description, p.app_id, p.repo_id, r.name, r.url, p.created_at
		FROM projects p LEFT JOIN repos r ON r.id = p.repo_id
		WHERE p.app_id = $1 ORDER BY p.name`, appID)
	if err != nil {
		return nil, fmt.Errorf("list projects: %w", err)
	}
	defer rows.Close()

	var projects []models.Project
	for rows.Next() {
		var p models.Project
		rows.Scan(&p.ID, &p.Name, &p.Description, &p.AppID, &p.RepoID, &p.RepoName, &p.RepoURL, &p.CreatedAt)
		projects = append(projects, p)
	}
	if projects == nil {
		projects = []models.Project{}
	}
	return projects, nil
}

func (r *appRepo) CreateProject(ctx context.Context, appID string, pc ProjectCreate) (*models.Project, error) {
	var p models.Project
	err := r.db.QueryRow(ctx, `
		INSERT INTO projects (name, description, app_id, repo_id)
		VALUES ($1, $2, $3, $4)
		RETURNING id, name, description, app_id, repo_id, created_at`,
		pc.Name, pc.Description, appID, pc.RepoID,
	).Scan(&p.ID, &p.Name, &p.Description, &p.AppID, &p.RepoID, &p.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("create project: %w", err)
	}
	return &p, nil
}

func (r *appRepo) UpdateProject(ctx context.Context, id string, upd ProjectUpdate) error {
	_, err := r.db.Exec(ctx, `
		UPDATE projects SET
			name        = COALESCE($2, name),
			description = COALESCE($3, description),
			repo_id     = CASE WHEN $4::text IS NOT NULL THEN $4::uuid ELSE repo_id END,
			updated_at  = NOW()
		WHERE id = $1`, id, upd.Name, upd.Description, upd.RepoID)
	return err
}

func (r *appRepo) DeleteProject(ctx context.Context, id string) error {
	_, err := r.db.Exec(ctx, `DELETE FROM projects WHERE id = $1`, id)
	return err
}

// projectsByAppIDs batch-loads projects for multiple app IDs (fixes N+1).
func (r *appRepo) projectsByAppIDs(ctx context.Context, appIDs []string) ([]models.Project, error) {
	if len(appIDs) == 0 {
		return nil, nil
	}
	rows, err := r.db.Query(ctx, `
		SELECT p.id, p.name, p.description, p.app_id, p.repo_id, r.name, r.url, p.created_at
		FROM projects p LEFT JOIN repos r ON r.id = p.repo_id
		WHERE p.app_id = ANY($1)
		ORDER BY p.app_id, p.name`,
		appIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var projects []models.Project
	for rows.Next() {
		var p models.Project
		rows.Scan(&p.ID, &p.Name, &p.Description, &p.AppID, &p.RepoID, &p.RepoName, &p.RepoURL, &p.CreatedAt)
		projects = append(projects, p)
	}
	return projects, nil
}
