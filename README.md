# HenKaiPan

![IMG](./assets/readme.png)

HenKaiPan is an ASPM platform that centralizes security scans, findings management, vulnerability intelligence, knowledge articles, policy automation, and AI-assisted remediation.

## Platform

The platform currently includes:

1. Dashboard
2. Scans
3. Findings
4. Vulns
5. Knowledge
6. Compliance
7. Reports
8. Apps
9. Repos
10. Settings

## Tech Stack

- **Frontend:** Astro 6 + Tailwind v4
- **API:** Go + chi
- **Database:** PostgreSQL 17 + pgx v5
- **Background jobs:** Redis 8 + Asynq
- **Scanners:** Dockerized tools such as Semgrep, Trivy, Gitleaks, Checkov, Nuclei, and more
- **AI features:** OpenRouter for remediation generation and finding validation

## Architecture Overview

HenKaiPan is split into three main runtime layers:

- **Frontend (`/frontend`)**: renders the UI and calls the backend API.
- **API (`/cmd/api`)**: exposes REST endpoints, authenticates users, reads/writes data, and enqueues async work.
- **Worker (`/cmd/worker`)**: consumes queued jobs, runs scanners in Docker containers, parses results, stores findings, and triggers AI validation.

PostgreSQL stores the platform state, while Redis/Asynq is used as the job queue between the API and the worker.

## High-Level Architecture Diagram

```mermaid
flowchart LR
    U[User] --> F[Astro Frontend]
    F -->|HTTP / JSON| API[Go API]

    API -->|CRUD + queries| DB[(PostgreSQL)]
    API -->|enqueue scan / validation jobs| Q[(Redis + Asynq)]

    Q --> W[Worker]
    W -->|read / write| DB
    W -->|docker run| S[Security Scanners]
    S -->|normalized findings| W

    API -->|AI remediation request| AI[OpenRouter]
    W -->|finding validation| AI
    AI -->|analysis / remediation content| API
    AI -->|validation result| W

    API -->|knowledge articles + findings + metrics| F
```

## Runtime Flow

### 1. User-facing request flow

```mermaid
sequenceDiagram
    participant User
    participant Frontend as Astro Frontend
    participant API as Go API
    participant DB as PostgreSQL

    User->>Frontend: Open dashboard / login / scans
    Frontend->>API: Call REST endpoints
    API->>DB: Read/write application data
    DB-->>API: Results
    API-->>Frontend: JSON response
    Frontend-->>User: Render updated UI
```

### 2. Scan execution flow

```mermaid
sequenceDiagram
    participant Frontend as Astro Frontend
    participant API as Go API
    participant Queue as Redis + Asynq
    participant Worker as Worker
    participant Scanner as Dockerized Scanner
    participant DB as PostgreSQL

    Frontend->>API: POST /api/scans
    API->>DB: Create scan record(s)
    API->>Queue: Enqueue scan job per scanner
    Queue->>Worker: Deliver TypeScanRun job
    Worker->>Scanner: Run scanner in Docker
    Scanner-->>Worker: Raw scan output
    Worker->>Worker: Parse + normalize findings
    Worker->>DB: Insert findings + update scan status
    Worker->>Queue: Enqueue agent validation jobs (optional)
```

### 3. AI remediation and validation flow

```mermaid
flowchart TD
    F[Finding stored in PostgreSQL] --> V[Optional validator job]
    V --> O[OpenRouter]
    O --> A[Confidence / FP likelihood]
    A --> DB[(PostgreSQL)]

    F --> R[User requests AI remediation]
    R --> API[API /api/knowledge/ai-remediate]
    API --> O
    O --> K[Markdown remediation article]
    K --> DB
    DB --> UI[Knowledge Center / Findings UI]
```

## Main Components

### Frontend

- Built with Astro and Tailwind.
- Uses `frontend/src/lib/api.ts` as the browser-side API client.
- Provides the dashboard, scans view, findings, vulns, knowledge center, reports, apps, repos, and settings.

### API

- Entry point: `cmd/api/main.go`
- Responsibilities:
  - JWT authentication and role-based authorization
  - REST endpoints for scans, findings, repos, apps, users, teams, policies, vulnerabilities, and knowledge
  - Metrics and export endpoints
  - Enqueueing asynchronous scan and validation jobs
  - AI remediation endpoint (`/api/knowledge/ai-remediate`)

### Worker

- Entry point: `cmd/worker/main.go`
- Responsibilities:
  - Consume Asynq jobs from Redis
  - Recover stuck scans on boot
  - Process `scan:run` jobs
  - Process `agent:validate` jobs when `OPENROUTER_API_KEY` is configured

### Scanning Engine

- Scanner registry: `internal/scanner/registry.go`
- Execution pipeline: `internal/tasks/generic.go`
- Supports multiple categories:
  - **SAST:** Semgrep, Gosec
  - **SCA:** Trivy, Grype, OSV-Scanner
  - **Secrets:** TruffleHog, Gitleaks
  - **IaC:** Checkov, tfsec, KICS
  - **Containers:** Trivy Image, Grype Image
  - **DAST:** Nuclei

All scanners are executed as Docker containers so the worker stays generic and scanner-specific behavior is defined by the registry.

### Data Layer

- PostgreSQL is the system of record.
- DB connection setup lives in `internal/db/postgres.go`.
- Repository layer lives under `internal/repository`.
- Migrations live in `/migrations` and are auto-run by Docker on container initialization.

### Queue Layer

- Redis is used by Asynq for background job transport.
- Queue bootstrap lives in `internal/queue/queue.go`.
- The API enqueues work; the worker consumes it.

### AI Layer

- OpenRouter integration lives in `internal/ai/openrouter.go`.
- AI is used for:
  - **Remediation generation** into knowledge articles
  - **Finding validation** to estimate confidence and false-positive likelihood

## Source Tree

```text
cmd/
  api/            # Go API entrypoint
  worker/         # Go worker entrypoint
frontend/
  src/            # Astro pages, layouts, API client
internal/
  handlers/       # HTTP handlers
  repository/     # PostgreSQL access layer
  scanner/        # Scanner registry + parsers
  tasks/          # Asynq task handlers
  ai/             # OpenRouter integration
  auth/           # JWT middleware and auth helpers
  db/             # pgx connection bootstrap
  queue/          # Redis/Asynq bootstrap
migrations/       # PostgreSQL schema and changes
docker/           # API and worker Dockerfiles
```

## Local Development

### Start infrastructure only

```bash
make dev-infra
```

### Start each service in separate terminals

```bash
make dev-api
make dev-worker
make dev-frontend
```

### Start the full stack with Docker Compose

```bash
make up
```

## Environment

Copy `.env.example` to `.env` and set at least:

```bash
DATABASE_URL=postgres://aspm:aspm@localhost:5432/aspm?sslmode=disable
REDIS_ADDR=localhost:6379
JWT_SECRET=change-me
ADMIN_USER=admin
ADMIN_PASS=admin
OPENROUTER_API_KEY=
OPENROUTER_MODEL=
```

If `OPENROUTER_API_KEY` is not configured, AI remediation and validation features are disabled.

## Screens

### Landing

![LANDING](./assets/landing.png)

### Dashboard

![DASH](./assets/dashboard.png)

### Vulns

![VULNS](./assets/vulns.png)
