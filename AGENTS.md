# AGENTS.md — appsec-aspm

## What runs where

- `cmd/api/main.go` boots the REST API: chi router, JWT middleware, CORS, Postgres store wiring, and the Redis queue client.
- `cmd/worker/main.go` boots the Asynq worker: recovers stuck scans on startup, registers `scan:run`, webhook, email, and optional AI jobs, then runs the queue server.
- `frontend/src/lib/api.ts` is the browser API client. It hardcodes `http://localhost:8080` as the backend base URL.

## Local dev commands

```bash
make dev-infra     # postgres + redis only
make dev-api       # go run ./cmd/api
make dev-worker    # go run ./cmd/worker
make dev-frontend  # cd frontend && pnpm dev
make up            # full docker compose stack
make down          # stop docker compose stack
make build         # builds bin/api and bin/worker
```

## Verified setup constraints

- Copy `.env.example` to `.env` before running anything.
- `internal/config/config.go` exits if `DATABASE_URL` or `JWT_SECRET` are missing.
- Default local ports are API `8080`, frontend `4321`, Postgres `5432`, Redis `6379`.
- `FRONTEND_BASE_URL` is optional but needed for external backlinks such as Jira finding URLs.
- AI features are per-task configurable (`AI_REMEDIATION_PROVIDER`, `AI_SUMMARY_PROVIDER`, `AI_VALIDATION_PROVIDER`) and can use OpenRouter or Cloudflare Workers AI.
- If AI provider credentials are missing, the worker does **not** register validation/summary handlers; remediation/validation features degrade instead of failing the whole app.

## Frontend gotchas

- Use `pnpm` inside `frontend/`; there is no root Node workspace.
- `frontend/src/pages/login.astro` posts directly to `http://localhost:8080/api/auth/login`.
- `frontend/src/lib/api.ts` also hardcodes `http://localhost:8080`; changing API host requires code changes, not just localStorage or env tweaks.
- The dashboard/settings UI stores `aspm_api_url` in localStorage, but the shared API client does not read it.
- Auth is bearer-token based and the frontend stores `aspm_token` in `localStorage`.

## Data / infra quirks

- `docker-compose.yml` mounts `./migrations` into `/docker-entrypoint-initdb.d`, so schema SQL auto-runs when the Postgres container initializes.
- `internal/db/postgres.go` is the only DB bootstrap; repositories are under `internal/repository`.
- The containerized worker mounts `/var/run/docker.sock` and `/tmp`; scanner execution depends on Docker being available.

## Product-model caveat

- The repo is mid-transition from legacy repo-centric flows to app/project-centric flows.
- Current API still exposes both legacy repo routes (`/api/repos`) and newer app/project routes (`/api/apps/{id}/projects`).
- `TODO.md` explicitly marks some repo-based metrics/vulnerability work as legacy. Do not assume the migration is complete when changing handlers, repositories, or frontend copy.

## Verification guidance

- There are no repo-local CI workflows or meaningful project tests checked in.
- Fastest trustworthy verification is usually:
  1. `make build`
  2. targeted manual API checks against `localhost:8080`
  3. targeted frontend verification with `make dev-frontend`

## High-value files

- `README.md` — current runtime architecture and local-dev prerequisites.
- `Makefile` — canonical dev/build commands.
- `docker-compose.yml` — service wiring, ports, migration mount, worker Docker socket mount.
- `internal/config/config.go` — required env vars and AI provider resolution.
- `TODO.md` — roadmap notes, including which repo-target concepts are legacy during the app/project reset.
