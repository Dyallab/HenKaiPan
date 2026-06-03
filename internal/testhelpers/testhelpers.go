// Package testhelpers provides shared test utilities for internal packages.
//
// Centralizes common test infrastructure: Redis test instances, loggers,
// context factories, and HTTP test helpers.
package testhelpers

import (
	"context"
	"log/slog"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

// NewMiniredis creates an in-memory Redis server for testing.
// Returns the redis client, the mini redis server (for direct manipulation),
// and a cleanup function.
//
// Usage:
//
//	rdb, mr, cleanup := NewMiniredis(t)
//	defer cleanup()
//
//	// Direct state manipulation for test setup:
//	mr.Set("key", "value")
func NewMiniredis(t testing.TB) (*redis.Client, *miniredis.Miniredis, func()) {
	t.Helper()

	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}

	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	cleanup := func() {
		rdb.Close()
		mr.Close()
	}

	return rdb, mr, cleanup
}

// NewTestLogger creates a slog.Logger that writes to the test log.
// Useful for packages that accept a logger and you want to see output
// on test failure.
func NewTestLogger(t *testing.T) *slog.Logger {
	t.Helper()
	return slog.New(slog.NewTextHandler(t.Output(), &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))
}

// DiscardLogger creates a slog.Logger that discalls all output.
// Use when the package under test requires a logger but you don't
// care about the output.
func DiscardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(discardWriter{}, nil))
}

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }

// BackgroundContext returns context.Background().
// Convenience wrapper for consistent usage.
func BackgroundContext() context.Context {
	return context.Background()
}
