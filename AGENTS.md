# AGENTS.md — HenKaiPan ASPM

## What runs where

- **API** (`cmd/api/main.go`): chi router, JWT auth, CORS, REST endpoints, enqueues jobs to Redis/Asynq
- **Worker** (`cmd/worker/main.go`): Asynq server, recovers stuck scans on startup, runs scan/validation/summary/webhook/email jobs
- **Frontend** (`frontend/`): Astro 6 + Tailwind v4, calls API via `frontend/src/lib/api.ts`
- **Database**: PostgreSQL 17 (source of truth)
- **Queue**: Redis 8 + Asynq (background job transport + SSE pub/sub relay between worker and API)

## Local dev commands

```bash
make dev-infra     # Start postgres + redis only
make dev-api       # air -c .air.toml (hot reload API)
make dev-worker    # air -c .air-worker.toml (hot reload worker)
make dev-frontend  # cd frontend && pnpm dev
make up            # Full docker compose stack (api, worker, postgres, redis, mailpit)
make down          # Stop docker compose stack
make build         # Builds bin/api and bin/worker
make migrate       # Manual migration: make migrate MIGRATION=migrations/xxx.sql
make sync-migrations # Sync root /migrations to internal/db/migrations/
```

## Required setup

1. **Copy `.env.example` to `.env`** — app exits if `DATABASE_URL`, `JWT_SECRET`, or `SECRET_ENCRYPTION_KEY` missing
2. **Default ports**: API `8080`, Frontend `4321`, Postgres `5432`, Redis `6379`, Mailpit `8025/1025`
3. **Scanner binaries**: Bundled in worker image — no Docker socket required

## Frontend gotchas

- Use `pnpm` inside `frontend/`; no root Node workspace
- `frontend/src/lib/api.ts` uses `PUBLIC_API_BASE` env var; defaults to current origin if unset
- Auth: bearer token stored in `localStorage` as `aspm_token`
- CORS allows: `http://localhost:4321`, `http://localhost:4322`, `http://localhost:3000`

## AI provider configuration

Per-task provider selection via env vars:
- `AI_REMEDIATION_PROVIDER`, `AI_SUMMARY_PROVIDER`, `AI_VALIDATION_PROVIDER` — `"cloudflare"` or `"openrouter"`
- If provider credentials missing, that feature degrades (no hard failure)
- Worker logs which handlers are registered at startup based on config

## Data / infra quirks

- **Migrations auto-run**: `./migrations` mounted to `/docker-entrypoint-initdb.d` in postgres container
- **Finding deduplication**: SHA256 fingerprint (`scanner:rule_id:file_path:line`) with `ON CONFLICT DO NOTHING`
- **Scanner packs**: `sast`, `sca`, `secrets`, `iac`, `containers` — resolved in `internal/scanner/registry.go`
- **DB bootstrap**: `internal/db/postgres.go` — single connection point, repositories under `internal/repository`

## Product model caveat

- **App** = optional business grouping (`app_id` can be NULL)
- **Project** = primary unit (users create, connect, scan, review)
- **Legacy routes**: `/api/repos` still exists but superseded by `/api/apps/{id}/projects`
- **TODO.md** marks repo-based metrics as legacy — verify before modifying handlers

## Verification guidance

No CI workflows or meaningful tests checked in. Fastest verification:
1. `make build` — ensures Go compiles
2. Manual API checks against `localhost:8080`
3. `make dev-frontend` — verify UI renders

## Queue architecture

- **Job types**: `scan:run` (3 retries, 30min timeout), `agent:validate` (5 retries), `webhook:send`, `email:send`
- **Dead Letter Queue**: exhausted retries go to DLQ — inspect via `asynqmon` or Redis CLI
- **Recovery**: worker recovers stuck scans on startup via `store.Scans.RecoverStuck()`
- **Metrics**: Prometheus at `:9090/metrics` (queue + DB stats)

## High-value files

| File | Purpose |
|------|---------|
| `README.md` | Architecture diagrams, runtime flows, screenshots |
| `Makefile` | Canonical dev/build commands |
| `docker-compose.yml` | Service wiring, migration mount |
| `internal/config/config.go` | Env var validation, AI provider resolution |
| `TODO.md` | Roadmap, legacy markers, commercialization context |
| `docs/queue-architecture.md` | Retry strategies, DLQ handling, monitoring setup |
| `frontend/src/lib/api.ts` | Browser API client, TypeScript interfaces |
| `migrations/*.sql` | Schema changes — numbered, auto-applied on container init |

## Demo workspace seed

```bash
docker compose exec -T postgres psql -U aspm -d aspm < scripts/seed-demo.sql
```
Creates sample project, 4 scans (semgrep/trivy/gitleaks), 9 findings with real CVEs.

## SQL safety rules (read before writing queries)

The repository layer (`internal/repository/`) MUST NOT use raw string interpolation for SQL.

### ✅ Approved patterns

```go
// 1. Static SQL with positional params — always preferred
rows, err := r.db.Query(ctx, `SELECT * FROM findings WHERE id = $1`, id)

// 2. pgx.NamedArgs — good for queries with many params
db.QueryRow(ctx, `
    INSERT INTO projects (name, repo_url)
    VALUES (@name, @repo_url)
    RETURNING id`,
    pgx.NamedArgs{"name": p.Name, "repo_url": p.RepoURL},
)

// 3. Dynamic WHERE building with parameterized values — SAFE
where = append(where, fmt.Sprintf("severity = ANY($%d)", argIdx))
args = append(args, f.Severities)
// Column names are hardcoded; values go through $N placeholders.

// 4. Dynamic param numbering for batch inserts — SAFE
valueStrings = append(valueStrings, fmt.Sprintf("($%d,$%d)", base+1, base+2))
// Builds $1, $2 placeholders, values passed via args slice.

// 5. Dynamic table names — use whitelist only (see helpers.go DeleteByID)
if !allowedDeleteTables[table] { return error }
db.Exec(ctx, fmt.Sprintf("DELETE FROM %s WHERE id = $1", table), id)
```

### ❌ Banned patterns

```go
// NEVER: string concat with user input
query := "SELECT * FROM findings WHERE severity = '" + severity + "'"

// NEVER: fmt.Sprintf with user values in SQL
query := fmt.Sprintf("SELECT * FROM findings WHERE severity = '%s'", severity)

// NEVER: LIMIT/OFFSET via %d — use $N params instead
// WRONG:
query += fmt.Sprintf(" LIMIT %d OFFSET %d", limit, offset)
// RIGHT:
query += ` LIMIT $3 OFFSET $4`
args = append(args, limit, offset)
```

### Why

PostgreSQL can't parameterize table/column names, LIMIT/OFFSET values, or sort columns. These go through `fmt.Sprintf` and risk SQL injection if user input reaches them. Always validate dynamic identifiers against a whitelist.

### 2026-06-02 audit result

All existing queries audited. One real injection risk fixed (`helpers.go` table whitelist), two LIMIT/OFFSET calls parameterized (`notification.go`, `vulnerability_new.go`). The patterns above are the residue — safe uses of `fmt.Sprintf` for parameter numbering, not value interpolation.

## Common pitfalls

- **No `.env`**: app exits immediately with structured error
- **Wrong Redis addr**: defaults to `localhost:6379`, override with `REDIS_ADDR`
- **Frontend API mismatch**: localStorage `aspm_api_url` not read by `api.ts` — hardcoded
- **AI features silent**: if no provider configured, handlers not registered — check worker logs
