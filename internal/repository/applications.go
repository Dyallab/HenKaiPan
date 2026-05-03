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
		WHERE ($1 = '' OR a.team_id = $1::uuid)
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
			if p.AppID == nil {
				continue
			}
			i := idx[*p.AppID]
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
	return DeleteByID(ctx, r.db, "apps", id)
}
