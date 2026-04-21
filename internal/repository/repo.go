package repository

import (
	"context"
	"fmt"

	"aspm/internal/models"

	"github.com/jackc/pgx/v5/pgxpool"
)

type repoRepo struct{ db *pgxpool.Pool }

func (r *repoRepo) List(ctx context.Context) ([]models.Repo, error) {
	rows, err := r.db.Query(ctx,
		`SELECT id, name, url, created_at FROM repos ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("repos list: %w", err)
	}
	defer rows.Close()

	var repos []models.Repo
	for rows.Next() {
		var repo models.Repo
		rows.Scan(&repo.ID, &repo.Name, &repo.URL, &repo.CreatedAt)
		repos = append(repos, repo)
	}
	if repos == nil {
		repos = []models.Repo{}
	}
	return repos, nil
}

func (r *repoRepo) Create(ctx context.Context, name, url string) (*models.Repo, error) {
	var repo models.Repo
	err := r.db.QueryRow(ctx,
		`INSERT INTO repos (name, url) VALUES ($1, $2) RETURNING id, name, url, created_at`,
		name, url,
	).Scan(&repo.ID, &repo.Name, &repo.URL, &repo.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("create repo: %w", err)
	}
	return &repo, nil
}
