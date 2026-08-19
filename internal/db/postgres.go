package db

import (
	"context"
	"log/slog"
	"os"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func Connect(connString string) *pgxpool.Pool {
	config, err := pgxpool.ParseConfig(connString)
	if err != nil {
		slog.Error("db parse config failed", "err", err)
		os.Exit(1)
	}
	// Set a per-connection statement_timeout as a safety net so a runaway
	// query (e.g. the vulnerability backfill loop) can never hang the worker
	// indefinitely. Individual queries that need more time can increase the
	// timeout via SET LOCAL statement_timeout within a transaction.
	config.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		_, err := conn.Exec(ctx, "SET statement_timeout = '5min'")
		return err
	}

	pool, err := pgxpool.NewWithConfig(context.Background(), config)
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
