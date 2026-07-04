package repository

import (
	"context"
	"fmt"

	"aspm/internal/models"

	"github.com/jackc/pgx/v5/pgxpool"
)

type appRepo struct{ db *pgxpool.Pool }

func (r *appRepo) List(ctx context.Context, teamFilter string) ([]models.App, error) {
	rows, err := r.db.Query(ctx, `
		SELECT a.id, a.name, a.description, a.team_id, t.name, a.created_at
		FROM apps a
		LEFT JOIN teams t ON t.id = a.team_id
		WHERE ($1 = '' OR a.team_id::text = $1)
		ORDER BY t.name NULLS LAST, a.name`, teamFilter)
	if err != nil {
		return nil, fmt.Errorf("apps list: %w", err)
	}
	defer rows.Close()

	var apps []models.App
	var ids []string
	for rows.Next() {
		var a models.App
		rows.Scan(&a.ID, &a.Name, &a.Description, &a.TeamID, &a.TeamName, &a.CreatedAt)
		a.Projects = []models.Project{}
		apps = append(apps, a)
		ids = append(ids, a.ID)
	}
	if apps == nil {
		return []models.App{}, nil
	}

	// Batch load all projects — fixes N+1
	projects, err := r.projectsByAppIDs(ctx, ids)
	if err == nil {
		idx := make(map[string]int, len(apps))
		for i, a := range apps {
			idx[a.ID] = i
		}
		for _, p := range projects {
			i := idx[p.AppID]
			apps[i].Projects = append(apps[i].Projects, p)
		}
	}

	return apps, nil
}

func (r *appRepo) Get(ctx context.Context, id string) (*models.App, error) {
	var a models.App
	err := r.db.QueryRow(ctx, `
		SELECT a.id, a.name, a.description, a.team_id, t.name, a.created_at
		FROM apps a LEFT JOIN teams t ON t.id = a.team_id
		WHERE a.id = $1`, id,
	).Scan(&a.ID, &a.Name, &a.Description, &a.TeamID, &a.TeamName, &a.CreatedAt)
	if err != nil {
		return nil, err
	}

	projects, _ := r.ListProjects(ctx, id)
	if projects == nil {
		projects = []models.Project{}
	}
	a.Projects = projects
	return &a, nil
}

func (r *appRepo) Create(ctx context.Context, name, description string, teamID *string) (*models.App, error) {
	var a models.App
	err := r.db.QueryRow(ctx, `
		INSERT INTO apps (name, description, team_id)
		VALUES ($1, $2, $3)
		RETURNING id, name, description, team_id, created_at`,
		name, description, teamID,
	).Scan(&a.ID, &a.Name, &a.Description, &a.TeamID, &a.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("create app: %w", err)
	}
	a.Projects = []models.Project{}
	return &a, nil
}

func (r *appRepo) Update(ctx context.Context, id string, upd AppUpdate) error {
	_, err := r.db.Exec(ctx, `
		UPDATE apps SET
			name        = COALESCE($2, name),
			description = COALESCE($3, description),
			team_id     = CASE WHEN $4::text IS NOT NULL THEN $4::uuid ELSE team_id END,
			updated_at  = NOW()
		WHERE id = $1`, id, upd.Name, upd.Description, upd.TeamID)
	return err
}

func (r *appRepo) Delete(ctx context.Context, id string) error {
	_, err := r.db.Exec(ctx, `DELETE FROM apps WHERE id = $1`, id)
	return err
}

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
