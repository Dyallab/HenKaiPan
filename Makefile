.PHONY: dev-api dev-worker dev-api-hot dev-worker-hot up down build build-bot test-race test-integration

ifneq (,$(wildcard .env))
  include .env
  export
endif

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
	go build $(LDFLAGS) -o bin/bot ./cmd/bot

build-bot:
	go build $(LDFLAGS) -o bin/bot ./cmd/bot

test-race:
	go test -race -count=1 ./...

test-integration:
	go test -race -count=1 -tags=integration ./internal/...
