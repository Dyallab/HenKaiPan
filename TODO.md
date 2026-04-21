# ASPM Roadmap

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
- [x] Repos page — add repo, scan shortcut
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
- [x] `GET /api/metrics/risk` — risk score per repo (critical×100 + high×20 + medium×5 + low×1, open only)
- [x] `GET /api/metrics/sla-compliance` — on-time %, overdue count, total tracked
- [x] `GET /api/findings/export` — CSV download with all lifecycle fields + auth via fetch+blob
- [x] Reports page — SLA compliance %, overdue KPI, open/resolved counts
- [x] Reports page — SVG line chart (findings trend, selectable 7/30/90/365d)
- [x] Reports page — Status distribution bars
- [x] Reports page — Risk score per repo horizontal bars
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
- [x] `POST /api/knowledge/ai-remediate` — genera guía con Claude claude-haiku-4-5 dado un finding_id, cachea resultado
- [x] CRUD admin: `POST/PUT/DELETE /api/knowledge/:slug`
- [x] `/dashboard/knowledge` — lista + buscador, visor markdown con prose styles, editor inline (admin), preview toggle
- [x] Cache-first: si existe artículo para ese rule_id, devuelve el curado sin llamar a Claude
- [x] Botón "Remediation Guide" en triage modal de findings → abre artículo o genera nuevo en tab
- [x] Requiere `ANTHROPIC_API_KEY` env var para generación IA (falla gracefully si no está seteada)

---

## Vulnerability Inventory ✅ (fuera de versión — entregado ad-hoc)

- [x] `GET /api/vulnerabilities` — agrupa findings por CVE/rule_id con conteos de repos/open/fixed
- [x] `GET /api/vulnerabilities/:id/affected` — repos afectados por vuln específica con status + assignees + deadline
- [x] `/dashboard/vulns` — tabla expandible por vuln, click → muestra todos los repos afectados
- [x] Header KPIs: unique vulns, critical count, max repos hit
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
- [ ] Email notifications (SMTP config)
- [ ] Jira integration: create ticket from finding
- [ ] GitHub integration: comment on PR with findings summary
- [ ] Webhook system: `POST /api/webhooks` + event delivery with retries
- [ ] Settings page — Notifications tab fully functional (wire to DB, not localStorage)

---

## Backlog / Nice-to-have

- [ ] SAML / OIDC SSO
- [ ] Finding deduplication across scans (same rule_id + file_path + line = same finding)
- [ ] Scan scheduling (cron-based periodic scans per repo)
- [ ] SBOM generation and tracking
- [ ] Container image scanning target type
- [ ] DAST target type (URL-based nuclei scans)
- [ ] Multi-tenant support (organizations)
- [ ] Audit log (who changed what, when)
