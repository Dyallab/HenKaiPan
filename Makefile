.PHONY: dev-api dev-worker dev-api-hot dev-worker-hot up down build test-race test-integration test-smoke seed-full verify-seed

ifneq (,$(wildcard .env))
  include .env
  export
endif

# Host-side integration/smoke runs target the published postgres port.
# .env's DATABASE_URL uses the compose service name (resolves only inside
# containers), so default TEST_DATABASE_URL to localhost (override in env).
TEST_DATABASE_URL ?= postgres://aspm:aspm@localhost:5432/aspm?sslmode=disable
export TEST_DATABASE_URL

VERSION ?= dev
BUILD_DATE ?= $(shell date -u '+%Y-%m-%d_%H:%M:%S')
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")

LDFLAGS := -ldflags "-X aspm/internal/handlers.Version=$(VERSION) -X aspm/internal/handlers.BuildDate=$(BUILD_DATE)"

dev-api:
	air -c .air.toml

dev-worker:
	air -c .air-worker.toml

dev: install-air
	air -c .air.toml &
	air -c .air-worker.toml

up:
	docker compose up --build

down:
	docker compose down

build:
	go build $(LDFLAGS) -o bin/api ./cmd/api
	go build $(LDFLAGS) -o bin/worker ./cmd/worker

test-race:
	go test -race -count=1 ./...

test-integration:
	# -p 1 serializes package binaries: they share one Postgres, so parallel
	# packages would pollute each other's tables despite per-test Reset.
	# Smoke stays out (own target test-smoke): Reset wipes the admin it needs.
	go test -race -count=1 -p 1 -tags=integration $(shell go list ./internal/... | grep -v /internal/smoke)

test-smoke:
	go test -race -count=1 -tags=integration ./internal/smoke/...

seed-full:
	docker compose exec -T postgres psql -U aspm -d aspm < scripts/seed-full.sql

verify-seed:
	docker compose exec -T postgres psql -U aspm -d aspm < scripts/verify-seed.sql
