.PHONY: dev-infra dev-api dev-worker dev-frontend dev-api-hot dev-worker-hot up down build tidy install-air

ifneq (,$(wildcard .env))
  include .env
  export
endif

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
	go build -o bin/api ./cmd/api
	go build -o bin/worker ./cmd/worker

tidy:
	go mod tidy
