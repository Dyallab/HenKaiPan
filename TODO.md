# Hen Kai Pan Roadmap

## Current Commercialization Focus

Target customer for the next stage:

- Small engineering teams / SMBs that do not have a hard compliance mandate yet
- Want fast security visibility without enterprise-heavy setup
- Need a credible path toward future SOC 2 / ISO 27001 readiness
- Care more about workflow simplicity, remediation speed, and executive visibility than deep enterprise governance on day 1

Commercial model:

- Primary offer: managed cloud SaaS with a monetizable plan structure
- Secondary offer: self-hosted edition for teams that want data/control boundaries, simpler procurement, or internal deployment requirements
- Product direction should preserve as much feature parity as possible between cloud and self-hosted, with clear packaging differences where needed

Product implication:

- Prioritize onboarding, repeatable scanning, remediation workflow, and lightweight reporting first
- Delay enterprise-only requirements unless they directly unblock trust or early sales
- Avoid hard-coupling core product value to cloud-only infrastructure unless there is a clear self-hosted fallback

## Product Reset Decision (current direction)

We can discard the current Apps / Repos / Scans structure and rebuild this area from zero.

New target product model:

- **App** = optional business grouping
- **Project** = primary technical unit and primary thing the user creates, connects, scans, and reviews
- **Standalone projects** are allowed (`project.app_id = NULL`)

---

## Version History

Version numbering follows the **self-hosted public release line**. The complete release history lives in the self-hosted CHANGELOG — this file only tracks planned work.

📖 **Full CHANGELOG:** [`HenKaiPan-self-hosted/CHANGELOG.md`](../HenKaiPan-self-hosted/CHANGELOG.md)

**Latest public release:** v1.16.0
**Next planned release:** v1.17.0

### Completed Releases (summary)

| Version | Key Changes |
|---------|-------------|
| v1.16.0 | SCA cross-scanner correlation, package matching, confidence score UI, corroborating scanners display |
| v1.15.0 | Project search bar, detail page, risk acceptance feature flag, rate limit increases, auth fixes |
| v1.14.0 | Private repo clone fix, findings loading fix, SQL correlation fix, scans page simplified |
| v1.13.1 | Migration 037 fix for fresh installs, seed script compat |
| v1.13.0 | Private repo token security (no leak in logs), PAT validation & expiry tracking, legacy repos table removed |
| v1.12.2 | Admin password reload on restart, settings tabs restructured, scanner cards simplified |
| v1.12.1 | Capability-based RBAC, viewer read-only access to findings |
| v1.12.0 | Error logging & format standardization, error sanitization, audit logging coverage |
| v1.11.0 | Role simplification (3→2), generic config/role guards, config status endpoint |
| v1.10.0 | Shell executor for scanners (KICS), container image scanning (trivy-image, grype-image) |
| v1.9.0 | License signing secret embedded in binary, random admin password on first run |
| v1.8.2 | PR merge ref clone fix, PR comments GITHUB_TOKEN passing |
| v1.8.1 | Migration idempotency, advisory locks, branch syntax in clone URL |
| v1.8.0 | CI/CD Integration API, API token management, GitHub Action, Marketplace publish |
| v1.7.0 | Installer improvements, auto-start stack, `--skip-ollama` flag |
| v1.6.0 | Per-app scan scheduling, GitHub repo discovery, bulk project import, vuln inventory |
| v1.5.1 | API Docker build fix (pnpm 11 compat) |
| v1.5.0 | Scanner binary execution (no Docker socket) |
| v1.4.0 | Defense-in-depth hardening, security headers, rate limiting |
| v1.3.0 | SSE real-time updates, AI summary dedup |
| v1.2.0 | Production docs, Kubernetes manifests, monitoring |
| v1.1.0 | Rate limiting, Ollama AI provider, Prometheus metrics |
| v1.0.0 | Initial self-hosted release |

> ⚠️ **Note:** The private repo had internal tags up to v1.6.2 that don't align with the public release line. Those tags are kept for Docker image references but are not considered official releases. Official releases follow the self-hosted CHANGELOG.

---

## Completed — Session: Error Handling & Middleware Audit

### Fixed
- **Rate limits too aggressive**: `rateLimitHeavy` 20→60 req/min, removed `/api/scans` from heavy (now falls under general 100 req/min)
- **Ownership middleware broken for viewers**: `extractResourceID` only matched singular resource names (`finding`) but URLs use plural (`/api/findings/`). Fixed to match both forms. Removed hardcoded `project` workaround that was the only working case.
- **Duplicate routes in main.go**: 3x Comments group, 2x Risk Acceptance group — removed duplicates
- **Error responses not logged**: `writeError()` was a silent function. Now logs code, message, status, path via `slog.ErrorContext` (196 call sites updated)
- **Error response format inconsistent**: Changed from `{"error": "msg"}` to `{"code": "...", "message": "..."}` across all handlers
- **Frontend error parsing**: `api.ts` now reads `err.message` first (new format), fallback to `err.error` (legacy). Error objects carry `code` and `status` properties for programmatic handling
- **Error details leaked in production**: Replaced DB/internal error strings with generic messages in 12 locations (schedules, projects, webhooks, settings, knowledge_remediation, knowledge_articles). Validation feedback errors (cron, URL, scanner names) kept as-is — user needs to know what's wrong
- **Audit logging gaps**: Added audit entries for App CRUD, Project CRUD, Webhook CRUD + test, Scan creation (single + batch). Coverage now: 10 entities, 30 audit points

### Skipped (documented for future)
- **Inconsistent error messages**: Cosmetic only. Frontend reads `code` field so behavior is predictable. Would require touching 200+ strings — high risk, low reward. See Tech Debt section.

---

## ✅ Released — v1.8.0: CI/CD Security Scanning

Shipped in self-hosted v1.8.0 (2026-05-14), with fixes in v1.8.1 and v1.8.2. Published to GitHub Marketplace.

### Implementation Status

| Component | Status |
|-----------|--------|
| Migration (`035_api_tokens.sql`) | ✅ Released |
| Token repository + interfaces | ✅ Released |
| Token CRUD API (`/api/v1/tokens`) | ✅ Released |
| External scan API (`/api/v1/scans/external`, `/status`) | ✅ Released |
| `APIKeyAuth` middleware | ✅ Released |
| Shared scan helpers (`resolveScanners`, `createScanRecords`) | ✅ Released |
| Documentation (`ci-cd-integration.md`) | ✅ Released |
| **UI: Settings → Tokens** | ✅ Released |
| **New repo: `henkaipan-action`** | ✅ Released |
| PR comments, fail-on-severity, Marketplace | ✅ Released (Marketplace published) |

### Features

- [x] **New repository** `Dyallab/henkaipan-action` (standalone repo, semver versioning)
- [x] **Docker-based GitHub Action** (Checkmarx-style)
  - [x] Action definition (`action.yml`) with `runs: using: 'docker'`
  - [x] Dockerfile with curl + jq (API communication)
  - [x] `entrypoint.sh` — main logic (trigger → poll → report → exit code)
  - [x] `cleanup.sh` — cleanup on cancellation
  - [x] Inputs: `api-url`, `api-key`, `project-id`, `scanners`, `fail-on-severity`, `scan-branch`, `post-pr-comment`
  - [x] Outputs: `scan-id`, `finding-count`, `finding-critical/high/medium/low`
  - [x] `fail-on-severity` blocks pipeline (exit code 1 when findings >= threshold)
  - [x] **Automatic PR comments** — posts a findings summary table to GitHub PRs; updates existing comment on re-run
- [x] `POST /api/v1/scans/external` — trigger scan from external CI/CD
  - [x] Auth via API key (header `X-API-Key`)
  - [x] Payload: `{ project_id, repo_url, scanners, branch }`
  - [x] Returns 202 Accepted + `scan_id`
  - [x] Worker clones the repo and runs the scans
- [x] `GET /api/v1/scans/{id}/status` — poll scan status
  - [x] States: `pending`, `running`, `completed`, `failed`
  - [x] Returns finding summary when completed
- [x] **Token management** (`/api/v1/tokens`)
  - [x] `POST /api/v1/tokens` — create token
  - [x] `GET /api/v1/tokens` — list tokens
  - [x] `DELETE /api/v1/tokens/{id}` — revoke token
  - [x] Per-project scope
  - [x] Hashed in DB (bcrypt), only shown on creation
  - [x] `hkp_` prefix for identification
- [x] **UI: Settings → Tokens**
  - [x] Token table with name, project, date, last used
  - [x] Revoke button with confirmation
  - [x] Creation modal with token copy

### Improvements

- [x] Automatic PR comments with finding summary
- [x] `fail-on-severity` to block CI (critical/high/medium)
- [x] README with quick start (< 2 minutes)
- [x] Publish to GitHub Marketplace
- [x] Setup guides: GitHub Actions, GitLab CI, Jenkins, CircleCI
- [x] Workflow examples: Node, Go, Python, Docker

### Security Considerations

- [x] Tokens with minimal scope (create scans only, no read access)
- [x] Never log tokens in requests or responses

### Connectivity Scenarios

| Scenario | Description | Solution |
|----------|-------------|----------|
| **Public SaaS** | Managed instance (`app.henkaipan.com`) | Action points to public URL ✅ |
| **Self-hosted (public URL)** | User exposes HenKaiPan at `henkaipan.company.com` | Action points to configured URL ✅ |
| **Self-hosted (VPN/private)** | HenKaiPan on internal network (`10.0.0.5`, `.internal`) | Requires **self-hosted runner** inside the network ✅ |

---

## v1.0 Release Candidate — Launch Blockers

Critical items that must be completed before v1.0 release.

### UX Improvements (Phase 2)

| Item | Effort | Priority |
|------|--------|----------|
| Scan coverage API + UI | 0.5 day | High |
| Finding comments thread | ✅ Done | High |
| Bulk operations (checkboxes + API) | ✅ Done | High |
| @username mentions in comments | 0.5 day | Low |
| In-app Documentation | ✅ Done | Medium |

- [ ] `GET /api/coverage` — scan coverage report (projects without scans in last N days)
- [ ] Projects page: "Never scanned" / "Last scan: X days ago" badges
- [ ] Projects filter: "Show only projects without recent scans"
- [x] Migration `031_finding_comments.sql` — comments table + triggers
- [x] `GET/POST /api/findings/:id/comments` — comments API (license-gated)
- [x] Comments thread UI in findings modal
- [ ] `@username` mentions in comments → email notification
- [x] Bulk operations: checkboxes in findings table
- [x] `PATCH /api/findings/bulk` — bulk status change, assignment, export
- [x] Bulk actions dropdown: change status, assign to user, export selected
- [x] **In-app Documentation** — static markdown pages explaining each section, accessible from sidebar "Documentation" link

### Credibility UI (v0.7 pending)

| Item | Effort | Priority |
|------|--------|----------|
| Credibility badges in findings table | ✅ Done | Medium |
| Credibility filters/sorting | ✅ Done | Medium |
| Correlation details modal | ✅ Done | Low |

- [x] Findings page — show credibility score and corroboration count badges
- [x] Add filters/sorting for credibility score
- [x] Correlation details endpoint (`GET /api/findings/{id}/correlations`)
- [x] Corroborating scanner names displayed in findings list
- [x] Dynamic correlation reason detection on detail page

### AI Notification Summaries (v0.6 pending)

| Item | Effort | Priority |
|------|--------|----------|
| AI summary generator for notifications | 1 day | High |
| User notifications system | ✅ Done | High |

- [ ] **AI notification summaries via small LLM** (e.g. Gemma 3 12B): generate human-readable digest from finding context for Slack/webhook/email notifications instead of raw JSON blobs. Uses task-specific model (e.g. `OLLAMA_MODEL` or `CF_MODEL_SUMM` depending on provider). Falls back to structured text if not configured.
- [x] **User notifications system** — in-app notifications with read/unread status, unread count badge, mark as read endpoints
- [x] `GET /api/notifications` — list user notifications
- [x] `GET /api/notifications/unread-count` — unread notification count
- [x] `PATCH /api/notifications/{id}/read` — mark single notification as read
- [x] `PATCH /api/notifications/read-all` — mark all notifications as read

### Onboarding & Growth

| Item | Effort | Priority |
|------|--------|----------|
| GitHub-first onboarding flow | 2-3 days | High |
| Product analytics + feedback | 1 day | Medium |
| Define packaging/limits | Meeting | Critical |
| Billing readiness | 2-3 days | Critical (cloud) |

- [ ] **GitHub-first onboarding flow** (token or app-based), optimized for small teams
- [ ] Capture product analytics + feedback prompts
- [ ] Define packaging/limits for early plans (cloud vs self-hosted)
- [ ] Billing readiness for cloud plans

---

## v1.0 Self-Hosted Edition

### Deployment & Distribution

| Item | Effort | Priority |
|------|--------|----------|
| Define self-hosted boundary | Meeting | Critical |
| Docker-compose install | 0.5 day | High |
| Production deployment guide | 1 day | High |
| Versioned release artifacts | 0.5 day | High |
| Upgrade path + release notes | 0.5 day | High |
| Data export/import | 1 day | Medium |
| Telemetry opt-in | 1 day | Low |

- [ ] Define self-hosted product boundary: what is included, what stays cloud-only, and why
- [x] Single-command/docker-compose install path for evaluation environments (v1.0 install.sh, improved in v1.7.0)
- [x] Production deployment guide (secrets, persistence, backups, upgrades, TLS, reverse proxy) — released v1.2.0 (`docs/production-deployment.md`)
- [x] Versioned release artifacts for self-hosted deployments (v1.0.0 through v1.16.0, published to GHCR)
- [x] Environment/config model that works cleanly in both cloud and self-hosted modes (unified `.env` model)
- [x] Upgrade path and release notes flow for self-hosted operators (CHANGELOG + docker-compose pull)
- [ ] **Automatic Update Check**: API detects new version in GHCR and notifies admin in UI
- [ ] **Safe-Update Flow**: Sequence for updating (DB Backup $\rightarrow$ Pull $\rightarrow$ Migrate $\rightarrow$ Restart)

- [ ] Data export / import strategy to support migration between cloud and self-hosted
- [ ] Minimal telemetry model for self-hosted (opt-in)

### Instance Management ✅

- [x] `GET /api/health` — health check endpoint (DB, Redis, Worker, disk status)
- [x] `/dashboard/system` — instance status page
- [x] `GET /api/version` — version endpoint
- [x] UI: version display + "new version available" indicator
- [x] Database migration system (`internal/db/migrate.go`)
- [x] Auto-run migrations on API startup

### Operational Documentation

| Item | Effort | Priority |
|------|--------|----------|
| Backup/restore docs | ❌ Removed | High |
| Worker scaling guide | 0.5 day | Medium |
| Scanner runtime requirements | 0.5 day | High |
| Troubleshooting guide | 1 day | High |
| Support model definition | Meeting | Medium |

- [x] Operational docs: backups, restore, worker scaling, scanner runtime requirements, troubleshooting — released v1.2.0 (`docs/operations.md`)
- [ ] Support model definition for self-hosted customers (SLA, update cadence, installation support boundaries)
- [x] Database migration documentation (auto-run on startup)

---

---

## Vulnerability Model — Cross-Batch Correlation & Dedup

Replace findings-as-primary with vulnerabilities-as-primary. Each real vulnerability (GHSA, CVE, secret hash, etc.) is a single `vulnerability` row with N linked findings as evidence across scans and batches.

### Why

| Problem | Current behavior | Target behavior |
|---------|-----------------|-----------------|
| Findings duplicados cross-batch | GHSA-389r aparece 4 veces en frontend (3 batches) | 1 vulnerability con 4 findings anidados |
| Correlación solo intra-batch | Confidence solo cuenta peers en el mismo scan | Confidence considera todos los scans del proyecto |
| No hay entidad "vulnerabilidad" | Frontend muestra findings planos | Frontend muestra vulnerabilidades agrupadas |
| Sin base para cross-engine | No hay donde colgar correlación SAST→DAST | `vulnerabilities` es la base para futura correlación cross-engine |

### Design

```
┌─────────────────────────────────────┐
│         vulnerabilities             │  ← entidad canónica
│  vuln_uid (deterministic per type)  │
│  project_id                         │
│  title / severity / status          │
│  first_seen_at / last_seen_at       │
│  scanner_coverage TEXT[]            │
│  finding_count                      │
│  confidence_score                   │
├─────────────────────────────────────┤
│  ┌─ findings (linked by vuln_id) ── │  ← evidencia
│  │  ID, scanner, batch, file, line │
│  │  pkg_name, pkg_version, ...     │
│  └───────────────────────────────── │
└─────────────────────────────────────┘
```

#### vuln_uid computation por engine

| Engine | vuln_uid = sha256(...) | Campos clave |
|--------|------------------------|-------------|
| SCA | `sca:{pkg_name}:{pkg_version}:{rule_id}` | pkg_name, pkg_version, rule_id |
| Secrets | `secret:{secret_hash}` | secret_hash |
| Containers | `container:{pkg_name}:{pkg_version}:{rule_id}` | pkg_name, pkg_version, rule_id |
| SAST | `sast:{rule_id}:{cwe_id}:{file_path}` | rule_id, cwe_id, file_path |
| IaC | `iac:{rule_id}:{file_path}` | rule_id, file_path |
| DAST | `dast:{rule_id}:{host}` | rule_id, matched_at |

### Migration Plan

| # | Step | Files | Effort | Depends on |
|---|------|-------|--------|-----------|
| 1 | Migration `040_vulnerabilities.sql` — crear tabla + índice + FK en findings | `internal/db/migrations/040_vulnerabilities.sql` | pequeña | - |
| 2 | Modelo `Vulnerability` + `vuln_uid` computation helpers por engine | `internal/models/models.go` | pequeña | #1 |
| 3 | `VulnerabilityRepository` interface + impl | `internal/repository/interfaces.go`, `internal/repository/vulnerability.go` | media | #2 |
| 4 | `FindVulnUID()` — compute vuln_uid para cada finding según su scanner/engine | `internal/scanner/registry.go` o nuevo `internal/vulnerability/uid.go` | media | #2 |
| 5 | Worker job: al insertar finding → upsert vulnerability + link finding | `internal/tasks/vulnerability.go` | media | #3, #4 |
| 6 | Backfill migration: `UPDATE findings SET vulnerability_id = ...` para rows existentes | `internal/db/migrations/040_vulnerabilities.sql` | media | #1, #4 |
| 7 | Confidence recalculation cross-batch usando `vulnerability.confidence_score` | `internal/repository/finding.go` — `recalculateConfidence` | media | #3 |
| 8 | API endpoint `GET /api/vulnerabilities` con filtros + paginación | `internal/handlers/vulnerability.go` | pequeña | #3 |
| 9 | API endpoint `GET /api/vulnerabilities/{id}/findings` | `internal/handlers/vulnerability.go` | pequeña | #3 |
| 10 | Frontend: Findings page → Vulnerabilities page con findings anidados | `frontend/src/pages/dashboard/vulnerabilities/` | grande | #8, #9 |
| 11 | Frontend: Finding detail → mostrar vuln context + siblings | `frontend/src/pages/dashboard/findings/detail.astro` | media | #9 |
| 12 | Frontend: Navegación + sidebar + breadcrumbs | `frontend/src/` | pequeña | #10 |
| 13 | Reemplazar `corroboration_count` estático por dynamic desde vuln | `internal/repository/finding.go` — `List` query | pequeña | #3 |
| 14 | E2E: test con scan múltiple del mismo target, verificar 1 vuln N findings | manual | pequeña | todo lo anterior |

### Implementation Order

```
Fase 1 — Core (backend)
  #1  →  #2  →  #3  →  #4  →  #5  →  #6
       └→ #7 (confidence upgrade)

Fase 2 — API (migrate existing endpoints + new)
  #8  →  #9  →  #10

Fase 3 — Frontend (migrate existing page + extend)
  #11 → #12 → #13 → #14 → #15

Fase 4 — QA
  #16
```

### Sub-tasks

#### Fase 1 — Core Backend

- [x] **#1 Migration `040_vulnerabilities.sql`**
  ```sql
  CREATE TABLE vulnerabilities (
      id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      vuln_uid        TEXT NOT NULL,
      project_id      UUID NOT NULL REFERENCES projects(id),
      title           TEXT NOT NULL,
      description     TEXT,
      severity        TEXT NOT NULL,
      status          TEXT NOT NULL DEFAULT 'open',
      engine_type     TEXT NOT NULL,
      pkg_name        TEXT,
      pkg_version     TEXT,
      cve_id          TEXT,
      cwe_id          TEXT,
      rule_id         TEXT,
      secret_hash     TEXT,
      file_path       TEXT,
      first_seen_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      last_seen_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      finding_count   INT NOT NULL DEFAULT 0,
      scanner_coverage TEXT[] NOT NULL DEFAULT '{}',
      confidence_score FLOAT,
      created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
  );
  CREATE UNIQUE INDEX idx_vulnerabilities_uid ON vulnerabilities (project_id, vuln_uid);
  ALTER TABLE findings ADD COLUMN vulnerability_id UUID REFERENCES vulnerabilities(id);
  CREATE INDEX idx_findings_vuln_id ON findings (vulnerability_id);
  ```

- [x] **#2 Modelo Vulnerability**
  - Struct `Vulnerability` en `internal/models/models.go`
  - Helpers `ComputeVulnUID(finding, engineType)` por engine type
  - Constantes `EngineSCA`, `EngineSecrets`, etc.

- [x] **#3 VulnerabilityRepository**
  - Interface con: `Upsert(ctx, v)`, `GetByUID(ctx, projectID, vulnUID)`, `List(ctx, filter)`, `GetFindings(ctx, vulnID)`, `RecalcConfidence(ctx, vulnID)`
  - Implementación en `internal/repository/vulnerability.go`
  - Agregar a `Stores` en `interfaces.go`

- [x] **#4 vuln_uid computation logic**
  - Nuevo paquete `internal/vulnerability/uid.go`
  - Función `Compute(finding, scannerCategory) → vulnUID`
  - Tests unitarios por engine type

- [x] **#5 Worker job: upsert vulnerability on finding insert**
  - Modificar `scan_run.go` — después de insertar finding, computar vuln_uid y hacer `vulnerabilityRepo.Upsert(ctx, ...)`
  - `Upsert` hace: `INSERT ... ON CONFLICT (project_id, vuln_uid) DO UPDATE SET last_seen_at=NOW(), finding_count=finding_count+1, scanner_coverage=array_append_unique(...)`
  - Manejar el caso `vuln_uid = NULL` (findings sin señales de correlación)

- [x] **#6 Backfill**
  - `BackfillVulnerabilities()` method in `VulnerabilityRepository` — processes findings with `vulnerability_id IS NULL` in batches of 500
  - Computes `vuln_uid`, upserts vulnerability, links findings, recalculates confidence
  - Runs at worker startup automatically

- [x] **#7 Confidence recalculation cross-batch**
  - `RecalcConfidence(vulnID)`: queries unique scanners across all linked findings for that vulnerability
  - Formula: `0.5 + 0.5 * (uniqueScanners - 1) / uniqueScanners` (capped at 1.0)
  - Called after each vulnerability upsert in `linkVulnerability` and after backfill

#### Fase 2 — API

- [x] **#8 `GET /api/vulnerabilities`**
  - Filtros: project_id, severity, status, engine_type, search (title/cve), page/limit
  - Sort: severity desc, last_seen_at desc, finding_count desc
  - Response: `{ vulnerabilities: [...], total, page, limit }`
  - Cada vulnerability incluye: id, title, severity, status, engine_type, first/last_seen, finding_count, scanner_coverage, confidence_score

- [x] **#9 `GET /api/vulnerabilities/{id}/findings`**
  - Retorna findings linkeados a esa vulnerabilidad
  - Incluye datos de correlación (scanner, batch, fecha, etc.)

#### Fase 3 — Frontend

> **State**: Ya existe `/dashboard/vulns` con `VulnInventory` que agrupa por `COALESCE(cve_id, rule_id)` vía `GET /api/vulnerabilities`. También existe `GET /api/vulnerabilities/{vulnID}/affected`. Esta fase migra la página existente a la tabla nueva + extiende funcionalidad.

- [x] **#10 Migrar `GET /api/vulnerabilities` a tabla `vulnerabilities`**
  - `ListVulnerabilities` handler ahora usa `VulnerabilityRepository.List()` ( tabla `vulnerabilities` )
  - Response shape cambiado de `VulnSummary` a `Vulnerability` — campos nuevos: `engine_type`, `confidence_score`, `first_seen_at`, `last_seen_at`, `scanner_coverage`, `id`, `vuln_uid`, `project_id`
  - Filtros nuevos: `project_id`, `engine_type`, `status`, `sort`
  - Frontend migrado: columna Engine, columna Confidence, scanner_coverage en vez de scanners

- [x] **#11 Migrar `GET /api/vulnerabilities/{vulnID}/affected` a tabla nueva**
  - `GetVulnerabilityAffected` ahora usa `VulnerabilityRepository.GetFindings()` — retorna `Finding[]`
  - Frontend migrado: expand muestra findings individuales en vez de affected repos

- [ ] **#12 Finding detail → contexto de vulnerabilidad**
  - Encontrar la página de detalle de finding (`/dashboard/findings/detail.astro`)
  - Agregar sección "Part of vulnerability" con link a vuln
  - Mostrar siblings (otros findings linkeados a la misma vuln)
  - Navegación entre siblings

- [ ] **#13 Vulnerabilities page — features pendientes**
  - ✅ Columna `engine_type` (SCA, SAST, Secrets, IaC, Containers, DAST)
  - ✅ Columna `confidence_score`
  - ✅ Expand row → findings individuales
  - ✅ Badge de scanner_coverage
  - [ ] Cambiar status de vulnerabilidad (no bulk)
  - [ ] Filtro por project_id en la UI

- [ ] **#14 Navigation**
  - Sidebar ya tiene "Vulnerabilities" → OK
  - Agregar link desde finding detail a su vulnerabilidad
  - Breadcrumbs: Vulnerabilities > Detail > Finding

- [ ] **#15 Reemplazar corroboration_count en List de findings**
  - La query de List puede seguir incluyendo `corroboration_count` pero ahora computado desde `vulnerability_id`
  - Opcional: reemplazar columna física por computada

#### Fase 4 — QA

- [ ] **#16 E2E test**
  - Escenario: 3 scans del mismo target en momentos distintos
  - Verificar: 1 vulnerabilidad por GHSA/CVE, N findings linkeados
  - Verificar: confidence_score aumenta con cada scan que confirma
  - Verificar: frontend muestra agrupado

### Notas técnicas

- **Coexistencia**: findings existentes no se modifican. La migration agrega `vulnerability_id` nullable. El sistema actual sigue funcionando mientras se migra.
- **vuln_uid NULL**: Findings sin señales de correlación (no rule_id, no pkg_name, no cve_id) quedan con `vulnerability_id = NULL`. La vista de findings los sigue mostrando.
- **Status propagation**: Si todos los findings de una vuln están `fixed`, la vuln pasa a `fixed`. Si alguno reabre → vuln vuelve a `open`.
- **Legacy support**: La API actual `GET /api/findings` sigue funcionando. La nueva vista de vulnerabilities es un endpoint aparte.
- **SCA vuln_uid simplificado**: SCA usa `sca:{ruleID}` como clave de correlación (no `sca:pkg:ver:ruleID`) porque el mismo GHSA/CVE es la misma vulnerabilidad independientemente de si el scanner reporta pkg_name o no. Los scanners reportan versiones distintas (osv-scanner: `5.16.5`, grype: `v5.16.5`) y la normalización de `v` prefix evita duplicados.
- **Version normalization**: `NormalizeVersion` quita prefijo `v` de package versions. `NormalizePath` quita `/tmp/aspm-scan-*` prefix de file paths. Ambas se aplican en `linkVulnerability` y `BackfillVulnerabilities`.

### Abierto / por resolver

- ¿El status de vulnerability se computa de los findings o se setea independientemente?

---

## Backlog / Post-v1.0 / Enterprise

### Enterprise Features

- [ ] SAML / OIDC SSO
- [ ] Multi-tenant support (organizations)
- [ ] Advanced RBAC (custom roles, granular permissions)
- [ ] Audit log export + SIEM integration

### Tech Debt

- [ ] **SQL Injection Audit**: Review all SQL queries for injection vulnerabilities
   - [ ] Audit all raw SQL queries (`db.Query`, `db.QueryRow`, `db.Exec`)
   - [ ] Verify parameterized queries are used everywhere (no string concatenation)
   - [ ] Check repository layer (`internal/repository/`) for dynamic query building
   - [ ] Review migration files for any dynamic SQL patterns
   - [ ] Scan for `fmt.Sprintf` used with SQL statements (common injection vector)

- [ ] **Migrate positional SQL params ($1, $2...) to pgx.NamedArgs (@name)**: Prevent off-by-one parameter bugs like the `findBatchMatches` incident where `$9` was skipped causing SQLSTATE 42P18 on every correlation query. Named params are self-documenting and eliminate renumbering errors.
   - [ ] `internal/repository/finding.go` — `findBatchMatches` ✅ (fixed), `getCorrelationContext`, `replaceCorrelationSet`, `recalculateConfidence`, `List`, `GetByID`, `Insert`, `ExportRows`
   - [ ] `internal/repository/finding_analysis.go` — `GetCorrelatedFindings`, `InsertCorrelations`
   - [ ] `internal/repository/vulnerability_new.go` — `Upsert`, `BackfillVulnerabilities`, `UpdateFindingVulnID`
   - [ ] `internal/repository/scan.go` — `Insert`, `GetByBatchID`, `RecoverStuck`
   - [ ] Other repository files with 4+ positional params

- [ ] **API versioning**: Migrate existing endpoints to `/api/v1/...`
  - [ ] Define migration strategy (co-locate `/api/` and `/api/v1/` during transition)
  - [ ] Migrate routes one by one (start with auth, then projects/scans/findings)
  - [ ] Update frontend to point to `/api/v1/`
  - [ ] Deprecate old `/api/` routes with `Deprecation` header
  - [ ] Rollback strategy

- [ ] **Inconsistent error messages** (cosmetic, low priority)
  - Backend returns ~200 different message strings for same error codes
  - Frontend now reads `code` field so this is non-blocking
  - Would require touching 200+ `writeError` calls — high risk, low reward
  - Consider doing incrementally as part of API versioning migration

### Scanner Extensions

- [ ] SBOM generation and tracking
- [x] Container image scanning target type (trivy-image, grype-image)
- [x] DAST target type (URL-based nuclei scans)
- [ ] Custom scanner plugins

### CI/CD & API Security

- [ ] Per-token rate limiting for API tokens
- [ ] Token rotation endpoint (optional)
- [ ] Validate `repo_url` is accessible before enqueuing external scans

### Platform Health

- [ ] **MCP Server for LLM Integration**: Expose HenKaiPan capabilities as an MCP server so LLMs/agents can interact with the platform programmatically
  - [ ] Research MCP protocol and tool definitions
  - [ ] Implement `tools/list` and `tools/call` endpoints
  - [ ] Expose key operations: list projects, trigger scans, query findings, get scan status
  - [ ] Authentication via API tokens (reuse existing token system)
  - [ ] Documentation for integrating with Claude, Cursor, etc.

- [ ] Scanner Health Dashboard — scanner failure rates, avg duration, success % table
- [ ] Queue monitoring dashboard (Asynq metrics)
- [ ] Performance profiling + optimization
- [ ] **Cache scanners in CI**: Worker Docker build is slow because it downloads all scanner binaries (semgrep, trivy, gitleaks, grype, etc.) from scratch each time. Add GitHub Actions caching for downloaded tarballs to reduce build time from ~10min to <2min

### Workflow Enhancements

- [ ] Finding templates (pre-defined triage workflows)
- [ ] Automated assignment rules (beyond policies)
- [ ] SLA customization per project/app
- [ ] Custom fields on findings

### Reporting & Compliance

- [ ] Scheduled report delivery (email/Slack)
- [ ] Custom report templates
- [ ] Compliance evidence collection automation
- [ ] Vendor risk assessment module

---

## Release Checklist (v1.0)

Before tagging v1.0:

- [ ] All Launch Blockers completed
- [ ] `make build` passes with version embedding
- [ ] Docker images built and pushed
- [ ] Deployment guide reviewed
- [ ] Database migration system tested end-to-end
- [ ] Demo workspace seed works
- [ ] License generator tested
- [ ] Changelog written
- [ ] GitHub release published
- [ ] Announcement prepared

---

## Notes

- **Scanner execution**: Scanners run as binaries via `os/exec` in the worker process — no Docker socket, no container isolation per scan
- **Repos page**: Legacy, superseded by Projects
- **Legacy repo references**: Some API endpoints still use "repo" terminology — migrate to "project"
- **PDF reports**: Browser print stylesheet exists, verify it works correctly
- **Credibility UI**: Complete — badges, sorting, corroborating scanner names, correlation reasons
- **pnpm 11**: Frontend Docker build requires `--ignore-scripts` + explicit `pnpm rebuild esbuild sharp`
