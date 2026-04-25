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

## v0.1 — Core Platform ✅

- [x] Go API (chi + pgx v5 + JWT auth)
- [x] Asynq worker + Redis queue
- [x] Docker-based scanner execution (semgrep, trivy, trufflehog, gosec, grype, gitleaks, checkov, nuclei)
- [x] Postgres schema (`001_init.sql`, `002_container_log.sql`)
- [x] Astro 4 + Tailwind v4 frontend (dark theme, Stitch design system)
- [x] Landing page (scanner showcase, feature bento grid)
- [x] Login page (JWT auth)
- [x] Dashboard — metrics cards, severity bars, scanner bars, recent scans
- [x] Scans page — scanner type badges, status dots, glow effects
- [x] Scan detail page — execution log, severity summary cards, findings table + modal
- [x] Findings page — severity/scanner filters, type badges
- [x] Repos page — add repo, scan shortcut (**legacy; superseded by Apps -> Projects reset direction**)
- [x] Compliance page — SOC2 / ISO 27001 / PCI-DSS frameworks, control mapping, TSV export
- [x] Settings page — General, Integrations, Notifications, Security tabs

---

## v0.2 — Finding Lifecycle + SLA ✅

- [x] Migration `003_lifecycle.sql` — adds `status`, `assigned_to`, `false_positive`, `notes`, `resolved_at`, `sla_deadline`
- [x] SLA deadlines auto-computed on finding insert (critical=24h, high=72h, medium=30d, low=90d)
- [x] Backfill SLA for existing findings on migration
- [x] `FindingStatus` constants (`open | in_review | accepted_risk | fixed | verified`)
- [x] `SLASummary` model + `GET /api/findings/sla` endpoint
- [x] `PATCH /api/findings/:id` — update status, assigned_to, false_positive, notes
- [x] `ListFindings` — status + overdue filters
- [x] Findings page — SLA summary bar (overdue / due today / on track / no deadline)
- [x] Findings page — status filter + overdue-only toggle
- [x] Findings page — status + SLA columns in table
- [x] Findings page — triage modal (status, assigned, false positive, notes, save)
- [x] Scan detail page — lifecycle triage section in finding modal

---

## v0.3 — Executive Reports & Trends ✅

- [x] `migrations/004_indexes.sql` — perf indexes on created_at + severity/status
- [x] `GET /api/metrics/trends?days=N` — findings over time grouped by day + severity
- [x] `GET /api/metrics/risk` — risk score per target (**legacy implementation used repo as the target**)
- [x] `GET /api/metrics/sla-compliance` — on-time %, overdue count, total tracked
- [x] `GET /api/findings/export` — CSV download with all lifecycle fields + auth via fetch+blob
- [x] Reports page — SLA compliance %, overdue KPI, open/resolved counts
- [x] Reports page — SVG line chart (findings trend, selectable 7/30/90/365d)
- [x] Reports page — Status distribution bars
- [x] Reports page — Risk score per target horizontal bars (**legacy implementation used repo**)
- [x] Reports page — Export CSV with severity + status filters
- [x] Add "Reports" nav item to `DashboardLayout.astro`
- [ ] PDF report generation (browser print stylesheet)

---

## v0.4 — Team & User Management ✅

- [x] Migration `006_users_teams.sql` — `users` table (id, username, email, password_hash, role: admin/analyst/viewer, last_login)
- [x] Migration `006_users_teams.sql` — `teams` table + `team_members` join
- [x] `GET/POST /api/users`, `PATCH/DELETE /api/users/:id` (admin only)
- [x] Role-based JWT claims (role + user_id in payload)
- [x] Auth middleware: `RequireRole()` per route (analyst gets 403 on admin routes)
- [x] `GET/POST /api/teams`, `DELETE /api/teams/:id`, `POST/DELETE /api/teams/:id/members`
- [x] `GET /api/me` — current user profile
- [x] Login response now includes `role` + `username`
- [x] Assignment autocomplete from users list in triage modal (datalist)
- [x] Settings page — Users tab (create user, change role, delete)
- [x] Settings page — Teams tab (create team, add/remove members)

---

## Knowledge Center ✅ (fuera de versión — entregado ad-hoc)

- [x] Migration `007_knowledge.sql` — `knowledge_articles` table (slug, title, content_md, tags[], cwe_ids[], rule_ids[], scanner, auto_generated)
- [x] 5 artículos curados sembrados: G304, G301, CKV2_GHA_1, Wildcard CORS, Missing USER in Dockerfile
- [x] `GET /api/knowledge` — lista con filtros (q, scanner, tag, cwe_id, rule_id)
- [x] `GET /api/knowledge/:slug` — artículo individual
- [x] `GET /api/knowledge/lookup` — lookup rápido por rule_id o cwe_id (para integraciones)
- [x] `POST /api/knowledge/ai-remediate` — genera guía vía OpenRouter dado un finding_id, cachea resultado
- [x] CRUD admin: `POST/PUT/DELETE /api/knowledge/:slug`
- [x] `/dashboard/knowledge` — lista + buscador, visor markdown con prose styles, editor inline (admin), preview toggle
- [x] Cache-first: si existe artículo para ese rule_id, devuelve el curado sin llamar al LLM
- [x] Botón "Remediation Guide" en triage modal de findings → abre artículo o genera nuevo en tab
- [x] Requiere `OPENROUTER_API_KEY` env var para generación IA (falla gracefully si no está seteada)

---

## Vulnerability Inventory ✅ (fuera de versión — entregado ad-hoc)

- [x] `GET /api/vulnerabilities` — agrupa findings por CVE/rule_id con conteos de activos escaneados/open/fixed (**legacy implementation used repos**)
- [x] `GET /api/vulnerabilities/:id/affected` — activos afectados por vuln específica con status + assignees + deadline (**legacy implementation used repos**)
- [x] `/dashboard/vulns` — tabla expandible por vuln, click → muestra todos los activos afectados (**legacy implementation used repos**)
- [x] Header KPIs: unique vulns, critical count, max affected targets (**legacy implementation used repos**)
- [x] Filtros: severity, texto libre (CVE/rule/title), open only toggle
- [x] CVE badge linkea a NVD, CWE badge linkea a MITRE
- [x] Repo card: progress bar open/fixed, assignees, SLA deadline, worst status dot

---

## v0.5 — Policies & Auto-Triage ✅

- [x] Migration `009_policies.sql` — `policies` + `suppressions` tables, `findings.suppressed` column
- [x] Policy engine: evaluate on finding insert (conditions: field/op/value; actions: set_status/assign)
- [x] Suppression engine: checks rule_id, scanner, file_pattern before insert, sets suppressed=true
- [x] `GET/POST/PATCH/DELETE /api/policies` (admin only)
- [x] `GET/POST/DELETE /api/suppressions` (admin only)
- [x] Settings page — Policies tab (rule builder UI with condition/action builder)
- [x] Settings page — Suppressions tab
- [x] `GET /api/findings` — suppressed hidden by default, `?suppressed=true` to show

---

## v0.6 — Notifications & Integrations

- [ ] Slack webhook: notify on new critical/high finding, SLA breach
- [ ] GitHub integration: comment on PR with findings summary
- [x] Webhook system: `POST /api/webhooks` + event delivery with retries
- [x] Settings page — Notifications tab fully functional (wire to DB, not localStorage)
- [x] Jira integration: create ticket from finding
- [ ] Email notifications (opcional)

---

## v0.7 — Finding Correlation & Credibility

- [x] Add `scan_batch_id` to group scanners launched together in a single run request
- [x] Correlate findings only inside the same `scan_batch_id`
- [x] Correlate only across scanners in the same family/category (SAST with SAST, secrets with secrets, etc.)
- [x] Store `finding_correlations` entries for same-family batch corroboration
- [x] Add base `confidence_score` + `corroboration_count` to findings
- [x] Credibility only increases on positive corroboration; no penalty when peers do not match
- [ ] Findings page — show credibility score and corroboration count badges
- [ ] Add filters/sorting for credibility score
- [ ] Add correlation details endpoint/UI for "which scanners corroborated this"

## v0.7.a - AI on-demand validation as a modifier on top of base credibility score

---

## v0.8 — First Paying Customers (SMB-ready)

- [ ] Onboarding wizard: first admin setup, first project creation, repo connection inside the project, first scan in <10 minutes
- [ ] Demo workspace / seeded sample data so prospects can evaluate value without scanning their own code first
- [ ] GitHub-first project onboarding flow (token or app-based), optimized for small teams
- [ ] Scan scheduling (cron-based periodic scans per project)
- [ ] Finding deduplication across scans (same rule_id + file_path + line = same finding)
- [ ] Default scanner packs/templates by use case (web app, API, IaC, container)
- [ ] Opinionated severity-based notification defaults so users get value without manual config
- [ ] Weekly executive digest email/PDF: new criticals, overdue items, trend summary, top projects at risk
- [ ] Finish launch-blocking work already identified in v0.3/v0.6/v0.7 (PDF reports, notifications, credibility UI)
- [ ] Basic in-product onboarding content: empty states, remediation hints, "what to do next" guidance
- [ ] Capture product analytics + feedback prompts to learn why early users convert or churn
- [ ] Define packaging/limits for early plans (cloud vs self-hosted; projects, scans/month, users, AI credits, support tier)
- [ ] Billing readiness for cloud plans (even if manual at first): usage visibility + Stripe-ready plan model

### v0.8.a — Domain Reset: Apps -> Projects

- [ ] Replace repo-as-asset with project-as-asset across schema, handlers, repository layer, worker inputs, and frontend API client
- [ ] Define final `projects` schema with `app_id NULL`, repo connection fields (`repo_url`, `provider`, `default_branch`, optional external repo id), and lifecycle metadata
- [ ] Make Apps optional grouping only: App 1:N Projects
- [ ] Add global Projects view with filters for `all / with app / without app`
- [ ] Add App detail/list view that creates and lists projects inside each app
- [ ] Remove standalone Repos page and replace it with Projects as the primary operational surface
- [ ] Rewire scans so they belong to `project_id` directly
- [ ] Reword UI copy, empty states, metrics, and reports from "repo(s)" to "project(s)" wherever the user-facing concept is the scanned asset

---

## v0.9 — Compliance Readiness Path

- [ ] Compliance starter mode: show "getting ready for SOC 2 / ISO 27001" instead of enterprise-heavy control management
- [ ] Guided policy packs mapped to common early-stage controls (access control, secrets, vulnerability management, cloud hygiene)
- [ ] Evidence-friendly exports: findings status, SLA handling, ownership, remediation history
- [ ] Audit log (who changed what, when)
- [ ] Risk acceptance / exception workflow with exportable rationale
- [ ] Lightweight asset inventory view for projects, apps, scanners, owners, and last scan coverage
- [ ] Compliance progress dashboard focused on readiness, not certification theater

---

## v1.0 — Self-Hosted Edition

- [ ] Define self-hosted product boundary: what is included, what stays cloud-only, and why
- [ ] Single-command/docker-compose install path for evaluation environments
- [ ] Production deployment guide for self-hosted (secrets, persistence, backups, upgrades, TLS, reverse proxy)
- [ ] Versioned release artifacts for self-hosted deployments
- [ ] Environment/config model that works cleanly in both cloud and self-hosted modes
- [ ] License key / entitlement model for paid self-hosted customers
- [ ] In-product license status / instance info page
- [ ] Upgrade path and release notes flow for self-hosted operators
- [ ] Data export / import strategy to support migration between cloud and self-hosted when feasible
- [ ] Minimal telemetry model for self-hosted (opt-in) so support and product learning do not depend on SaaS-only visibility
- [ ] Operational docs: backups, restore, worker scaling, scanner runtime requirements, troubleshooting
- [ ] Support model definition for self-hosted customers (SLA, update cadence, installation support boundaries)

---

## Backlog / Later / Enterprise

- [ ] SAML / OIDC SSO
- [ ] SBOM generation and tracking
- [ ] Container image scanning target type
- [ ] DAST target type (URL-based nuclei scans)
- [ ] Multi-tenant support (organizations)
