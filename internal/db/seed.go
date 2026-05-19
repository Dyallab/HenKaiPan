package db

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

// EnsureAdminUser reads ADMIN_USER and ADMIN_PASS from env and upserts
// the admin user on every startup. This keeps the password in sync
// with .env even if the user already exists.
func EnsureAdminUser(ctx context.Context, pool *pgxpool.Pool) {
	adminUser := os.Getenv("ADMIN_USER")
	if adminUser == "" {
		adminUser = "admin"
	}

	adminPass := os.Getenv("ADMIN_PASS")
	if adminPass == "" {
		slog.Warn("ADMIN_PASS not set — admin user password will not be synced")
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(adminPass), bcrypt.DefaultCost)
	if err != nil {
		slog.Error("failed to hash admin password", "err", err)
		return
	}

	email := fmt.Sprintf("%s@localhost", adminUser)

	_, err = pool.Exec(ctx,
		`INSERT INTO users (username, email, password_hash, role)
		 VALUES ($1, $2, $3, 'admin')
		 ON CONFLICT (username) DO UPDATE SET
			password_hash = EXCLUDED.password_hash,
			email = EXCLUDED.email`,
		adminUser, email, string(hash),
	)
	if err != nil {
		slog.Error("failed to upsert admin user", "err", err)
		return
	}

	slog.Info("admin user synced", "username", adminUser)
}
