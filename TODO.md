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

**Latest public release:** v1.15.0
**Next planned release:** v1.16.0

### Completed Releases (summary)

| Version | Key Changes |
|---------|-------------|
| v1.15.0 | Project search bar, detail page, risk acceptance feature flag, rate limit increases, auth fixes |
| v1.14.0 | Private repo clone fix, findings loading fix, SQL correlation fix, scans page simplified |
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

## v1.8.0 — GitHub Action: CI/CD Security Scanning

### Implementation Status

| Component | Status |
|-----------|--------|
| Migration (`035_api_tokens.sql`) | ✅ Done |
| Token repository + interfaces | ✅ Done |
| Token CRUD API (`/api/v1/tokens`) | ✅ Done |
| External scan API (`/api/v1/scans/external`, `/status`) | ✅ Done |
| `APIKeyAuth` middleware | ✅ Done |
| Shared scan helpers (`resolveScanners`, `createScanRecords`) | ✅ Done |
| Documentation (`ci-cd-integration.md`) | ✅ Done |
| **UI: Settings → Tokens** | ✅ Done |
| **New repo: `henkaipan-action`** | ✅ Done |
| PR comments, fail-on-severity, Marketplace | 🔜 Marketplace pending |

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
- [ ] Publish to GitHub Marketplace
- [x] Setup guides: GitHub Actions, GitLab CI, Jenkins, CircleCI
- [x] Workflow examples: Node, Go, Python, Docker

### Security Considerations

- [x] Tokens with minimal scope (create scans only, no read access)
- [ ] Per-token rate limiting
- [x] Never log tokens in requests or responses
- [ ] Token rotation (optional)
- [ ] Validate repo_url is accessible before enqueuing

### Connectivity Scenarios

| Scenario | Description | Solution |
|----------|-------------|----------|
| **Public SaaS** | Managed instance (`app.henkaipan.com`) | Action points to public URL ✅ |
| **Self-hosted (public URL)** | User exposes HenKaiPan at `henkaipan.company.com` | Action points to configured URL ✅ |
| **Self-hosted (VPN/private)** | HenKaiPan on internal network (`10.0.0.5`, `.internal`) | Requires **self-hosted runner** inside the network |

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
| Credibility badges in findings table | 0.5 day | Medium |
| Credibility filters/sorting | 0.5 day | Medium |
| Correlation details modal | 0.5 day | Low |

- [ ] Findings page — show credibility score and corroboration count badges
- [ ] Add filters/sorting for credibility score
- [x] Correlation details endpoint (`GET /api/findings/{id}/correlations`)

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
- [ ] Single-command/docker-compose install path for evaluation environments
- [ ] Production deployment guide (secrets, persistence, backups, upgrades, TLS, reverse proxy)
- [ ] Versioned release artifacts for self-hosted deployments
- [ ] Environment/config model that works cleanly in both cloud and self-hosted modes
- [ ] Upgrade path and release notes flow for self-hosted operators
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

- [ ] Operational docs: backups, restore, worker scaling, scanner runtime requirements, troubleshooting
- [ ] Support model definition for self-hosted customers (SLA, update cadence, installation support boundaries)
- [x] Database migration documentation (auto-run on startup)

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
- **Credibility UI**: Backend done, frontend pending
- **pnpm 11**: Frontend Docker build requires `--ignore-scripts` + explicit `pnpm rebuild esbuild sharp`
