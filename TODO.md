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

## Completed Versions

### v0.1 — Core Platform ✅

- [x] Go API (chi + pgx v5 + JWT auth)
- [x] Asynq worker + Redis queue
- [x] Scanner binary execution (semgrep, trivy, trufflehog, gosec, grype, gitleaks, checkov, nuclei, osv-scanner, tfsec, kics)
- [x] Postgres schema (`001_init.sql`, `002_container_log.sql`)
- [x] Astro 4 + Tailwind v4 frontend (dark theme, Stitch design system)
- [x] Landing page (scanner showcase, feature bento grid)
- [x] Login page (JWT auth)
- [x] Dashboard — metrics cards, severity bars, scanner bars, recent scans
- [x] Scans page — scanner type badges, status dots, glow effects
- [x] Scan detail page — execution log, severity summary cards, findings table + modal
- [x] Findings page — severity/scanner filters, type badges
- [x] Compliance page — SOC2 / ISO 27001 / PCI-DSS frameworks, control mapping, TSV export
- [x] Settings page — General, Integrations, Notifications, Security tabs

### v0.2 — Finding Lifecycle + SLA ✅

- [x] Migration `003_lifecycle.sql` — adds `status`, `assigned_to`, `false_positive`, `notes`, `resolved_at`, `sla_deadline`
- [x] SLA deadlines auto-computed on finding insert (critical=24h, high=72h, medium=30d, low=90d)
- [x] `FindingStatus` constants (`open | in_review | accepted_risk | fixed | verified`)
- [x] `PATCH /api/findings/:id` — update status, assigned_to, false_positive, notes
- [x] Findings page — SLA summary bar, status filter, triage modal

### v0.3 — Executive Reports & Trends ✅

- [x] `GET /api/metrics/trends`, `/api/metrics/risk`, `/api/metrics/sla-compliance`
- [x] Reports page — SVG line chart, status distribution, risk score bars
- [x] CSV export with filters
- [x] PDF report generation (browser print stylesheet)

### v0.4 — Team & User Management ✅

- [x] Users table with roles (admin/analyst/viewer)
- [x] Teams + team_members join table
- [x] Role-based auth middleware
- [x] Settings page — Users and Teams tabs

### v0.5 — Policies & Auto-Triage ✅

- [x] Policies + suppressions tables
- [x] Policy engine: conditions + actions on finding insert
- [x] Settings page — Policies and Suppressions tabs

### v0.6 — Notifications & Integrations ✅

- [x] Slack webhook integration
- [x] GitHub App integration (PR comments with findings)
- [x] Webhook system with retries
- [x] Jira integration
- [x] Email notifications (Brevo/Mailpit with provider abstraction)

### v0.7 — Finding Correlation & Credibility ✅

- [x] `scan_batch_id` for grouping scanners
- [x] Cross-scanner correlation (same family, same batch)
- [x] `confidence_score` + `corroboration_count` on findings

### v0.8 — First Paying Customers (SMB-ready) ✅

- [x] Scan scheduling (cron-based per project)
- [x] Finding deduplication (SHA256 fingerprint)
- [x] Scanner packs (`all`, `sast`, `sca`, `secrets`, `iac`, `containers`)
- [x] In-product onboarding wizard
- [x] Weekly executive digest email
- [x] Demo workspace seed script

### v0.8.a — Domain Reset: Apps -> Projects ✅

- [x] Schema reset: projects with `app_id NULL`, `repos` table dropped
- [x] Global Projects view with app filters
- [x] Scans belong to `project_id` directly

### v0.9 — Compliance Readiness Path ✅

- [x] Compliance starter mode (SOC 2 / ISO 27001 readiness)
- [x] Guided policy packs
- [x] Audit log + risk acceptance workflow (license-gated)
- [x] Asset inventory view

### v0.10 — Commercial Features ✅

- [x] License system with offline JWT validation
- [x] Feature gates for paid functionality (Comments, Audit Log, Risk Acceptance, Reports)
- [x] User notifications system (in-app, unread tracking)
- [x] Database migration framework
- [x] Finding summary endpoint (`POST /api/findings/{id}/summary`)

### v1.3.0 — Defense in Depth ✅

- [x] Security hardening: `cap_drop ALL` + minimal `cap_add`, `no-new-privileges`, seccomp profiles
- [x] Input validation: backend (go-playground/validator) + frontend (Zod)
- [x] Rate limiting (Redis-based, fails closed)
- [x] JWT hardening: no default secret, expiration required
- [x] Security headers: CSP, X-Frame-Options, HSTS
- [x] IDOR prevention: ownership middleware with admin bypass

### v1.4.0 — Docker Socket Removed ✅

- [x] Worker no longer mounts `/var/run/docker.sock` — scanners run as binaries via `os/exec`
- [x] All scanner binaries bundled in worker Docker image (multi-stage build)
- [x] Non-root user (uid 1000) in worker container
- [x] Go 1.26 runtime seccomp compatibility (`clone`, `clone3`, `arch_prctl`, `mbind`)

### v1.4.1 — Scanner Build Fixes ✅

- [x] Checkov pip installation (Alpine musl compat)
- [x] Semgrep pysemgrep wrapper for Python module execution
- [x] GitHub release URL fixes for scanner binaries

### v1.5.0 — Scanner Registry Cleanup ✅

- [x] Removed `Image`, `MountDst`, `Entrypoint`, `ExtraVolumes` fields from Scanner struct (dead code from Docker era)
- [x] Deleted standalone scanner Dockerfiles (`docker/scanners/`)
- [x] Fixed semgrep exit code 2 (target path argument bug)
- [x] Removed `build-scanner-slim` and `build-all` Makefile targets
- [x] Deleted `buildDockerCmd()` dead code
- [x] Removed Docker socket mount from Kubernetes manifests
- [x] Updated all documentation to reflect embedded binary execution model

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

### Scanner Extensions

- [ ] SBOM generation and tracking
- [x] Container image scanning target type (trivy-image, grype-image)
- [x] DAST target type (URL-based nuclei scans)
- [ ] Custom scanner plugins

### Platform Health

- [ ] Scanner Health Dashboard — scanner failure rates, avg duration, success % table
- [ ] Queue monitoring dashboard (Asynq metrics)
- [ ] Performance profiling + optimization

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
