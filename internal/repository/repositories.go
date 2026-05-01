package repository

import (
	"context"
	"fmt"

	"aspm/internal/models"
	"aspm/internal/secrets"

	"github.com/jackc/pgx/v5/pgxpool"
)

type repoRepo struct{ db *pgxpool.Pool }

func (r *repoRepo) List(ctx context.Context) ([]models.Repo, error) {
	rows, err := r.db.Query(ctx,
		`SELECT id, name, url, github_token IS NOT NULL as has_token, created_at FROM repos ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("repos list: %w", err)
	}
	defer rows.Close()

	var repos []models.Repo
	for rows.Next() {
		var repo models.Repo
		if err := rows.Scan(&repo.ID, &repo.Name, &repo.URL, &repo.HasToken, &repo.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan repo: %w", err)
		}
		repos = append(repos, repo)
	}
	return EnsureSlice(repos), nil
}

func (r *repoRepo) Create(ctx context.Context, name, url string) (*models.Repo, error) {
	var repo models.Repo
	err := r.db.QueryRow(ctx,
		`INSERT INTO repos (name, url) VALUES ($1, $2) RETURNING id, name, url, false, created_at`,
		name, url,
	).Scan(&repo.ID, &repo.Name, &repo.URL, &repo.HasToken, &repo.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("create repo: %w", err)
	}
	return &repo, nil
}

func (r *repoRepo) Delete(ctx context.Context, id string) error {
	return DeleteByID(ctx, r.db, "repos", id)
}

func (r *repoRepo) UpdateGitHubToken(ctx context.Context, id, token string) error {
	if token == "" {
		_, err := r.db.Exec(ctx, `UPDATE repos SET github_token = NULL WHERE id = $1`, id)
		return err
	}

	encrypted, err := secrets.Encrypt(token)
	if err != nil {
		return fmt.Errorf("encrypt token: %w", err)
	}

	_, err = r.db.Exec(ctx, `UPDATE repos SET github_token = $1 WHERE id = $2`, encrypted, id)
	return err
}

func (r *repoRepo) GetGitHubToken(ctx context.Context, id string) (string, error) {
	var token *string
	err := r.db.QueryRow(ctx, `SELECT github_token FROM repos WHERE id = $1`, id).Scan(&token)
	if err != nil {
		return "", fmt.Errorf("get token: %w", err)
	}
	if token == nil || *token == "" {
		return "", nil
	}

	decrypted, err := secrets.Decrypt(*token)
	if err != nil {
		return "", fmt.Errorf("decrypt token: %w", err)
	}
	return decrypted, nil
}
