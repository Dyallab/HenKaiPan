package repository

import (
	"context"
	"fmt"

	"aspm/internal/models"

	"github.com/jackc/pgx/v5/pgxpool"
)

type userRepo struct{ db *pgxpool.Pool }

func (r *userRepo) List(ctx context.Context) ([]models.User, error) {
	rows, err := r.db.Query(ctx,
		`SELECT id, username, email, role, created_at, last_login FROM users ORDER BY created_at`)
	if err != nil {
		return nil, fmt.Errorf("users list: %w", err)
	}
	defer rows.Close()

	var users []models.User
	for rows.Next() {
		var u models.User
		if err := rows.Scan(&u.ID, &u.Username, &u.Email, &u.Role, &u.CreatedAt, &u.LastLogin); err != nil {
			continue
		}
		users = append(users, u)
	}
	if users == nil {
		users = []models.User{}
	}
	return users, nil
}

func (r *userRepo) GetByID(ctx context.Context, id string) (*models.User, error) {
	var u models.User
	err := r.db.QueryRow(ctx,
		`SELECT id, username, email, role, created_at, last_login FROM users WHERE id = $1`, id,
	).Scan(&u.ID, &u.Username, &u.Email, &u.Role, &u.CreatedAt, &u.LastLogin)
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func (r *userRepo) Create(ctx context.Context, u UserCreate) (*models.User, error) {
	var out models.User
	err := r.db.QueryRow(ctx,
		`INSERT INTO users (username, email, password_hash, role)
		 VALUES ($1, $2, $3, $4)
		 RETURNING id, username, email, role, created_at, last_login`,
		u.Username, u.Email, u.PasswordHash, u.Role,
	).Scan(&out.ID, &out.Username, &out.Email, &out.Role, &out.CreatedAt, &out.LastLogin)
	if err != nil {
		return nil, fmt.Errorf("create user: %w", err)
	}
	return &out, nil
}

func (r *userRepo) Update(ctx context.Context, id string, upd UserUpdate) (*models.User, error) {
	_, err := r.db.Exec(ctx, `
		UPDATE users SET
			email         = COALESCE($2, email),
			role          = COALESCE($3, role),
			password_hash = COALESCE($4, password_hash)
		WHERE id = $1`,
		id, upd.Email, upd.Role, upd.PasswordHash)
	if err != nil {
		return nil, fmt.Errorf("update user: %w", err)
	}
	return r.GetByID(ctx, id)
}

func (r *userRepo) Delete(ctx context.Context, id string) error {
	_, err := r.db.Exec(ctx, `DELETE FROM users WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete user: %w", err)
	}
	return nil
}

func (r *userRepo) GetCredentials(ctx context.Context, username string) (id, hash, role string, err error) {
	err = r.db.QueryRow(ctx,
		`SELECT id, password_hash, role FROM users WHERE username = $1`, username,
	).Scan(&id, &hash, &role)
	return
}

func (r *userRepo) UpdateLastLogin(ctx context.Context, id string) error {
	_, err := r.db.Exec(ctx, `UPDATE users SET last_login = NOW() WHERE id = $1`, id)
	return err
}
