.PHONY: dev-infra dev-api dev-worker dev-frontend dev-api-hot dev-worker-hot up down build tidy install-air migrate sync-migrations gen-license test test-coverage test-race test-integration

ifneq (,$(wildcard .env))
  include .env
  export
endif

VERSION ?= dev
BUILD_DATE ?= $(shell date -u '+%Y-%m-%d_%H:%M:%S')
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")

LDFLAGS := -ldflags "-X aspm/internal/handlers.Version=$(VERSION) -X aspm/internal/handlers.BuildDate=$(BUILD_DATE)"

dev-infra:
	docker compose up postgres redis -d

dev-api:
	air -c .air.toml

dev-worker:
	air -c .air-worker.toml

dev-frontend:
	cd frontend && pnpm dev

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

tidy:
	go mod tidy

# (usage: make migrate MIGRATION=migrations/029_xxx.sql)
migrate:
	@if [ -z "$(MIGRATION)" ]; then echo "Error: MIGRATION is required. Usage: make migrate MIGRATION=migrations/029_xxx.sql"; exit 1; fi
	cat $(MIGRATION) | docker compose exec -T postgres psql -U aspm -d aspm

sync-migrations:
	@echo "Syncing migrations to internal/db/migrations..."
	@rm -rf internal/db/migrations/*.sql
	@cp migrations/*.sql internal/db/migrations/
	@echo "Done. $(shell ls internal/db/migrations/*.sql | wc -l) migration files synced."

test:
	go test -race -count=1 ./internal/...

test-coverage:
	go test -race -count=1 -coverprofile=/tmp/cover.out ./internal/...
	go tool cover -html=/tmp/cover.out -o /tmp/cover.html
	@echo "Coverage report: /tmp/cover.html"
	@go tool cover -func=/tmp/cover.out | tail -1

test-race:
	go test -race -count=1 ./...

test-integration:
	go test -race -count=1 -tags=integration ./internal/...

gen-license:
	./scripts/generate-license.sh $(EMAIL) $(DAYS)
