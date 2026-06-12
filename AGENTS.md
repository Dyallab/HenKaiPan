# HenKaiPan — AGENTS.md

## Binaries

- **API** (`cmd/api/main.go`): chi router, JWT auth, REST handlers. Build tag `embed_frontend` embeds `frontend/dist/` into binary.
- **Worker** (`cmd/worker/main.go`): Asynq consumer. Runs scans, AI validation, webhooks, emails, digests. Recovers stuck scans + backfills vulnerabilities on startup.
- **Bot** (`cmd/bot/main.go`): Scaffolding only — no implementation yet.

## Dev environment

- `.envrc` → `direnv` loads Nix dev shell + `dotenv .env` automatically on `cd` into repo.
- `.env` is **required** (copied from `.env.example`). App exits if `DATABASE_URL`, `JWT_SECRET`, or `SECRET_ENCRYPTION_KEY` missing.
- No `.air.toml` files in repo (gitignored or local). `air` still works — just needs the config file.

## Commands

| What | How |
|------|-----|
| Start infra (postgres + redis) | `nix run .#dev-infra` |
| Dev API (air hot-reload) | `make dev-api` |
| Dev worker (air hot-reload) | `make dev-worker` |
| Dev frontend (pnpm) | `nix run .#dev-frontend` |
| Full Docker stack | `make up` / `make down` |
| Build Go binaries (quick) | `make build` |
| Build Go binaries (obfuscated) | `nix run .#build-obfuscated` |
| Build all (nix) | `nix build .#{api,worker,bot,full}` |
| Tests (internal/) | `nix run .#test` |
| Tests (all packages) | `make test-race` |
| Tests (integration tag) | `make test-integration` |
| Test coverage | `nix run .#test-coverage` |
| Go mod tidy | `nix run .#tidy` |
| Run migration | `nix run .#migrate -- migrations/xxx.sql` |
| Sync migration dirs | `nix run .#sync-migrations` |
| Seed demo workspace | `docker compose exec -T postgres psql -U aspm -d aspm < scripts/seed-demo.sql` |
| Generate license | `nix run .#gen-license -- email days` |

## Architecture

- **30 packages** under `internal/` — entrypoints under `cmd/`. All Go code imports from `aspm/...`.
- **Repository layer** (`internal/repository/`): single `NewPostgresStores(pool, redisAddr)` factory. Repos accessed via `store.X` throughout handlers/tasks.
- **Queue** (`internal/queue/`): Asynq client + server. Job types: `scan:run` (3 retries, 30min timeout), `agent:validate` (5 retries), `webhook:send`, `email:send`, `snippet:enrich`, `digest:send`, `report:send`.
- **SSE bridge** (`internal/events/redis_bridge.go`): worker publishes events to Redis pub/sub; API subscribes and relays to SSE clients.
- **AI providers**: OpenRouter / Cloudflare / Ollama. Per-task selection via `AI_{REMEDIATION,SUMMARY,VALIDATION}_PROVIDER`. If unconfigured, handlers silently not registered — check worker logs.
- **License** (`internal/license/`): offline HMAC-SHA256 validation. Feature gates: comments, audit-log, risk-acceptance, reports, ai-remediation, teams, policies, scheduling, integrations, email-notifications.
- **Scanner packs**: `sast`, `sca`, `secrets`, `iac`, `containers` — resolved in `internal/scanner/registry.go`. Scanner binaries bundled in worker Docker image.

## Key quirks

- **Migrations live in two places**: `migrations/` (source) and `internal/db/migrations/` (embedded copy). **Must be identical.** CI checks `diff -rq`. Sync with `nix run .#sync-migrations`.
- **Frontend embed**: `go build -tags embed_frontend` compiles Astro build into the API binary. Without the tag, API serves no frontend — run Astro separately.
- **CORS defaults**: `http://localhost:4321`, `4322`, `3000`. Override with `CORS_ALLOWED_ORIGINS`.
- **Auth token**: Stored in `localStorage` as `aspm_token`. External CI/CD endpoints (`/api/v1/scans/external`) use `X-API-Key` header instead of JWT.
- **`/api/repos` is legacy** — superseded by `/api/apps/{id}/projects`.

## Tests

- **27 test files** across internal packages. Most are unit tests with no external dependencies.
- **No repository integration tests exist yet** (`internal/repository/` has zero test files). The agreed strategy: shared Docker PG (`docker compose up postgres`) with per-test schema isolation — `internal/testhelpers/` needs `NewTestDB` implemented.
- Redis-using tests use `miniredis` via `testhelpers.NewMiniredis(t)` — no real Redis needed.

## SQL rules (enforced)

- **Never** string-interpolate user values into SQL — use `$N` positional params.
- Dynamic identifiers (table names, sort columns) validated against a whitelist — see `helpers.go DeleteByID`.
- LIMIT/OFFSET must be `$N` params, never `%d`.
- All queries were audited 2026-06-02. One real injection risk fixed, two LIMIT/OFFSETs parameterized.

## CI/CD (`.github/workflows/ci-cd.yml`)

- **test**: `go test -race -count=1 ./internal/...` (Go 1.26).
- **check-migrations**: `diff -rq migrations/ internal/db/migrations/`.
- **api / worker**: Docker build+push to `ghcr.io/dyallab/henkaipan-{api,worker}` on tag push (v\*). Cached via GitHub Actions cache.
