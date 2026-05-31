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

📖 **Full CHANGELOG:** [`github.com/Dyallab/HenKaiPan-self-hosted`](https://github.com/Dyallab/HenKaiPan-self-hosted/blob/main/CHANGELOG.md)

**Current release:** v1.19.1 (2026-05-29)
**Next planned:** v1.20.0

### Completed Releases (summary)

| Version | Key Changes |
|---------|-------------|
| v1.19.1 | MCP SSE endpoint event format fix (plain URL string for SSEClientTransport compat) |
| v1.19.0 | MCP Server for LLM Integration (SSE transport, 7 tools), finding detail vulnerability context card, vuln page status dropdown + project filter, breadcrumb navigation, `corroboration_count`→dynamic subquery migration, E2E vulnerability correlation test |
| v1.18.0 | Vulnerability status management (PATCH endpoint + UI dropdown), project filter on vulns page, breadcrumb navigation, vulnerability context in finding detail, finding model enriched with `vulnerability_id` |
| v1.17.0 | Vulnerability model — cross-batch correlation & dedup, vuln_uid per engine, automatic linking + backfill, cross-batch confidence scoring, version check endpoint, repository layer migrated to named params |
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

## 🔜 v1.20.0 — Visibility Sprint

### Scan Coverage

- [x] `GET /api/coverage` — scan coverage report (projects without scans in last N days, default 30) *(route was missing, handler/repo/frontend already existed)*
- [x] Project cards: "Never scanned" / "Last scan: X days ago" badge on each project *(already implemented in frontend)*
- [x] Projects filter: "Show only projects without recent scans" toggle/filter *(already implemented in frontend)*

### Scanner Health

- [x] Scanner Health Dashboard — failure rates, avg duration, success % per scanner *(endpoint + page created)*
- [ ] Queue monitoring dashboard (Asynq metrics exposure)

### Platform Health

- [x] **Cache scanners in CI**: Consolidated scanner downloads into single RUN with pinned versions for deterministic Docker layer caching via `cache-from: type=gha`. Eliminated `curl \| sh` and `latest/download` URLs.

---

## Backlog

### UX & Quality of Life

- [ ] `GET /api/coverage` — scan coverage report (projects without scans in last N days)
- [ ] Projects page badges: "Never scanned" / "Last scan: X days ago"
- [ ] Projects filter: "Show only projects without recent scans"
- [ ] `@username` mentions in comments → email notification
- [ ] AI notification summaries via small LLM (Gemma 3 12B or similar) — human-readable digest for Slack/webhook/email instead of raw JSON

### Onboarding & Growth

- [ ] GitHub-first onboarding flow (token or app-based), optimized for small teams
- [ ] Capture product analytics + feedback prompts
- [ ] Define packaging/limits for early plans (cloud vs self-hosted)
- [ ] Billing readiness for cloud plans

### Instance Management

- [ ] Define self-hosted product boundary: what is included, what stays cloud-only, and why
- [ ] **Automatic Update Check**: API detects new version in GHCR and notifies admin in UI
- [ ] **Safe-Update Flow**: sequence for updating (DB Backup → Pull → Migrate → Restart)
- [ ] Data export/import strategy to support migration between cloud and self-hosted
- [ ] Minimal telemetry model for self-hosted (opt-in)
- [ ] Support model definition for self-hosted customers (SLA, update cadence, installation support boundaries)

### Enterprise Features

- [ ] SAML / OIDC SSO
- [ ] Multi-tenant support (organizations)
- [ ] Advanced RBAC (custom roles, granular permissions)
- [ ] Audit log export + SIEM integration

### Tech Debt

- [ ] **SQL Injection Audit**: review all raw SQL queries for injection vulnerabilities
  - [ ] Audit all raw SQL queries (`db.Query`, `db.QueryRow`, `db.Exec`)
  - [ ] Verify parameterized queries everywhere (no string concatenation)
  - [ ] Check repository layer for dynamic query building
  - [ ] Review migration files for any dynamic SQL patterns
  - [ ] Scan for `fmt.Sprintf` used with SQL statements
- [ ] **API versioning**: migrate existing endpoints to `/api/v1/...` with deprecation strategy
  - [ ] Define migration strategy (co-locate `/api/` and `/api/v1/` during transition)
  - [ ] Migrate routes one by one (start with auth, then projects/scans/findings)
  - [ ] Update frontend to point to `/api/v1/`
  - [ ] Deprecate old `/api/` routes with `Deprecation` header
  - [ ] Rollback strategy
- [ ] **Inconsistent error messages**: ~200 message strings for same error codes. Frontend reads `code` field so non-blocking. Consider doing incrementally as part of API versioning migration.

### Scanner Extensions

- [ ] SBOM generation and tracking
- [ ] Custom scanner plugins (community-contributed scanners with standardized interface)
- [ ] **Scanner Marketplace** (largo plazo) — discovery, install, and cross-correlation of third-party scanners; requires standardized plugin contract, sandboxed execution, and contribution guidelines

### CI/CD & API Security

- [ ] Per-token rate limiting for API tokens
- [ ] Token rotation endpoint (optional)
- [ ] Validate `repo_url` is accessible before enqueuing external scans

### Platform Health

- [ ] Scanner Health Dashboard — failure rates, avg duration, success % table
- [ ] Queue monitoring dashboard (Asynq metrics)
- [ ] Performance profiling + optimization
- [ ] **Cache scanners in CI**: Worker Docker build downloads all scanner binaries from scratch. Add GitHub Actions caching for downloaded tarballs to reduce build time from ~10min to <2min

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

## Notes

- **Scanner execution**: Scanners run as binaries via `os/exec` in the worker process — no Docker socket, no container isolation per scan
- **Repos page**: Legacy, superseded by Projects
- **Legacy repo references**: Some API endpoints still use "repo" terminology — migrate to "project"
- **PDF reports**: Browser print stylesheet exists, verify it works correctly
- **Credibility UI**: Complete — badges, sorting, corroborating scanner names, correlation reasons
- **pnpm 11**: Frontend Docker build requires `--ignore-scripts` + explicit `pnpm rebuild esbuild sharp`

---

*Última actualización: 2026-05-31*
