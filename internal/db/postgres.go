package db

import (
	"context"
	"log/slog"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"
)

func Connect(connString string) *pgxpool.Pool {
	pool, err := pgxpool.New(context.Background(), connString)
	if err != nil {
		slog.Error("db connect failed", "err", err)
		os.Exit(1)
	}
	if err := pool.Ping(context.Background()); err != nil {
		slog.Error("db ping failed", "err", err)
		os.Exit(1)
	}
	slog.Info("database connected")
	return pool
}
