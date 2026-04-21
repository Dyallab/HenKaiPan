.PHONY: dev-infra dev-api dev-worker dev-frontend up down build tidy

ifneq (,$(wildcard .env))
  include .env
  export
endif

dev-infra:
	docker compose up postgres redis -d

dev-api:
	go run ./cmd/api

dev-worker:
	go run ./cmd/worker

dev-frontend:
	cd frontend && pnpm dev

up:
	docker compose up --build

down:
	docker compose down

build:
	go build -o bin/api ./cmd/api
	go build -o bin/worker ./cmd/worker

tidy:
	go mod tidy
