# AGENTS.md — ASPM

Go API + worker (chi, pgx v5, Asynq/Redis) + Astro 6 frontend (Tailwind v4).

## Startup

```bash
# Infra (postgres + redis)
make dev-infra

# Development (3 terminals)
make dev-api      # localhost:8080
make dev-worker  # background jobs
make dev-frontend  # localhost:4321
```

Or full stack: `make up` (docker compose).

## Env Required

Copy `.env.example` → `.env`:
- `DATABASE_URL=postgres://aspm:aspm@localhost:5432/aspm?sslmode=disable`
- `REDIS_ADDR=localhost:6379`
- `JWT_SECRET`, `ADMIN_USER`, `ADMIN_PASS`
- `OPENROUTER_API_KEY` (for AI remediation and validator features)
- `OPENROUTER_MODEL` (optional, defaults to `openai/gpt-4.1-mini`)

## Tech Stack

| Layer | Tool |
|-------|------|
| API router | chi/v5 |
| DB | pgx v5 (PostgreSQL 17) |
| Queue | Asynq (Redis 8) |
| Auth | JWT (golang-jwt v5) |
| Worker | Asynq background tasks |
| Scanners | Docker containers (semgrep, trivy, etc.) |
| Frontend | Astro 6, Tailwind v4, Chart.js |

## Structure

```
/cmd/api, /cmd/worker    # Entrypoints
/internal/handlers       # HTTP handlers (chi routes)
/internal/repository    # pgx queries
/internal/models        # DB models
/internal/tasks         # Asynq task definitions
/migrations/*.sql       # Schema (run via docker-init)
/frontend/src           # Astro pages + components
```

## Key Patterns

- **Migrations**: Auto-run on container init via `/docker-entrypoint-initdb.d`. Numbered prefix (`001_*.sql`).
- **Auth**: JWT claims include `role` + `user_id`. Use `RequireRole()` middleware for admin routes.
- **SLA**: Auto-computed on finding insert (critical=24h, high=72h, medium=30d, low=90d).
- **Scanners**: Run in Docker, executed by worker via container. Results parsed into findings.
- **AI Remediation**: `POST /api/knowledge/ai-remediate` calls OpenRouter. Requires `OPENROUTER_API_KEY`.

## Testing

- No test framework currently configured
- Manual verification via UI or API calls (`curl localhost:8080/...`)

## Frontend Notes

- Uses pnpm (not npm/yarn)
- `npm run dev` won't work - use `pnpm dev` or `make dev-frontend`
- Dark theme, Stitch design system in `stitch-designs/`

## Existing Instructions

- Full roadmap: `TODO.md`
