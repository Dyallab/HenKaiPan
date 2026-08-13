# Hen Kai Pan Roadmap

## Product Direction

---

## Version History

Version numbering follows the **self-hosted public release line**. The complete release history lives in the self-hosted CHANGELOG — this file only tracks planned work.

📖 **Full CHANGELOG:** [`github.com/Dyallab/HenKaiPan-self-hosted`](https://github.com/Dyallab/HenKaiPan-self-hosted/blob/main/CHANGELOG.md)

**Current release:** v1.30.2 (2026-06-18)

### Completed Releases (summary)

| Version | Key Changes |
|---------|-------------|
| v1.30.2 | Datascope authorization — team-scoped vulns/audit logs/schedules, admin-only resource creation, viewer UI hardening |
| v1.30.1 | MCP response format — handlers return MCP-standard `content` array for LLM client compatibility |
| v1.30.0 | Ponytail over-engineering audit — removed bot, testhelpers, duplicate code. CI permissions fix, secrets key derivation fix, rate limit atomicity fix, event metadata fix |
| v1.29.1 | Simplified README, removed deprecated X-XSS-Protection header, backup script |
| v1.29.0 | Full pentest hardening sprint — SSRF, rate limiting, session invalidation, role change hardening, email verification, cookie security, webhook DNS rebinding |
| v1.28.1 | CI security gate for Docker builds, telemetry endpoint hardcoded |
| v1.28.0 | Tier limits (projects/users/AI scans), anonymous telemetry, `GET /api/limits` |
| v1.27.0 | Open source prep, MIT license, community templates, cloud pricing tiers |
| v1.26.0 | License system removed — all features free, no license key required |
| v1.25.0 | Auto-create project from external scan, action v1.5.0 |
| v1.24.0 | Slack interactive bot, bulk findings actions, Nix dev environment |
| v1.23.0 | Project tags, security scores, scheduled report delivery, knowledge article improvements, bulk findings export with consistent snippet display |
| v1.22.0 | Finding detail perf overhaul (Redis cache, composite endpoint, ~20s→&lt;10ms), SSE memory leak/over-fetching fixes, ENABLE_PPROF, pnpm pinned |
| v1.20.5 | GetByID query fix — missing argument caused pgx error, breaking finding detail and dependant endpoints |
| v1.20.4 | MCP session context fix (r.Context → context.Background), rate limit 10/token, token last_used tracking in auth middleware |
| v1.20.3 | MCP Streamable HTTP only — removed legacy SSE transport, POST-only endpoint |
| v1.20.2 | MCP dual transport (SSE + Streamable HTTP) for backward compatibility |
| v1.20.1 | MCP Streamable HTTP transport fix (POST returns JSON directly, session via header) |
| v1.20.0 | Scanner Health Dashboard (endpoint + admin page), scan coverage endpoint + badges/filter, CI cache (consolidated scanner downloads into single RUN) |
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
| v1.9.0 | License signing secret embedded in binary (removed in v1.26.0), random admin password on first run |
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

> ⚠️ **Note:** Pre-v1.0.0 internal development tags don't align with the public release line. Those tags are kept for Docker image references but are not considered official releases. Official releases follow the self-hosted CHANGELOG.

---

## ✅ v1.24.0 — Released (2026-06-16)

SMB workflow & visibility — Slack bot, bulk actions, Nix dev environment.

- [x] **Bulk Findings Actions**: multi-select findings → batch status change / assign / dismiss
- [x] **Slack Interactive Bot**: Slack Socket Mode bot for triage (acknowledge, dismiss, assign) directly from Slack — interactive buttons via Block Kit

---

## ✅ v1.30.2 — Released (2026-06-18)

Datascope authorization enforcement — close gaps left after v1.29.0 team-scoped access.

- [x] **Datascope on vulnerability queries**: `GET /api/vulnerabilities` and `GET /api/vulnerabilities/engine-summary` filter by team membership
- [x] **Datascope on audit logs**: `GET /api/audit-logs` scoped to current user for non-admin roles
- [x] **Datascope on schedules**: `GET /api/schedules` filters by team membership
- [x] **Admin-only write endpoints**: `POST /api/apps`, `POST /api/projects`, bulk create/assign require admin role
- [x] **Viewer UI hardening**: hide admin nav/actions; guard findings bulk actions and user assignment
- [x] **Findings page 403 toast**: stop calling admin-only `/api/users` for viewers

---

## ✅ v1.30.1 — Released (2026-06-18)

MCP LLM client compatibility fix.

- [x] **MCP response format**: handlers use `mcpToolResult` wrapper — MCP-standard `content` array instead of bare JSON

---

## ✅ v1.30.0 — Released (2026-06-17)

Ponytail over-engineering audit + hardening fixes.

- [x] **Over-engineering audit**: removed bot binary, dead `internal/testhelpers/`, consolidated duplicate rate limiters
- [x] **CI workflow permissions**: top-level `permissions:` block to prevent GITHUB_TOKEN over-scoping
- [x] **Secrets key derivation**: `hex.DecodeString` for hex-encoded encryption keys (was incorrect SHA256)
- [x] **Rate limit atomicity**: single Redis pipeline for `Incr` + `Expire` on login rate limiting
- [x] **Event metadata propagation**: `Metadata.ProjectID` set in scan creation and schedule event constructors

---

## 🛡️ Security Hardening (Pentest 2026-06-16)

Findings from internal pentest — see [`pentest/reports/INDEX.md`](../pentest/reports/INDEX.md) for full context.

### Sprint 1 — High (completed in v1.29.0)

- [x] **R003 — Require `current_password` on password change**
  - Require `current_password` on `PATCH /api/users/{id}` for own password changes (CWE-620, CVSS 8.1)
  - Separate `POST /api/users/{id}/reset-password` endpoint for admin resets + notify the affected user
  - Invalidate active sessions on password change
  - Reference: [`R003`](../pentest/reports/R003-password-change-no-current-password.md)
- [x] **R002 — Re-authentication for role changes**
  - Require `current_password` on `PATCH /api/users/{id}` when modifying the `role` field (CWE-269, CVSS 7.2)
  - Notify the affected user by email when their role changes (which admin, from what IP)
  - Active alerts for `user.update` with `role` change in audit log
  - Reference: [`R002`](../pentest/reports/R002-privilege-escalation-role-change.md)

### Sprint 2 — Medium (completed in v1.29.0)

- [x] **R001 — Git host allowlist in scan `target`**
  - Validate URL against allowlist: `github.com`, `gitlab.com`, `bitbucket.org` (CWE-918, CVSS 5.0)
  - Resolve hostname and block RFC1918, link-local, and loopback ranges before `git clone`
  - Consider DMZ for the scan runner (no internal network access)
  - Reference: [`R001`](../pentest/reports/R001-ssrf-scan-target.md)
- [x] **R006 — Rate limiting on `POST /api/auth/login`**
  - Rate limiting by IP and by username via Redis (CWE-307, CVSS 5.3)
  - Max 5 failed attempts per username in 5 min → `429 Too Many Requests` + `Retry-After`
  - Temporary account lockout after N failures (e.g., 10) + email notification
  - Verify/create rate limiting rule in Cloudflare WAF for this route
  - Reference: [`R006`](../pentest/reports/R006-no-rate-limiting-login.md)

### Sprint 3 — Low (completed in v1.29.0)

- [x] **R004 — Email verification on address change**
  - Require `current_password` on `PATCH /api/users/{id}` when modifying `email`
  - Notify the **previous** email of the change (via `email:send` queue)
  - In-app notification + email to new address via `notifySecurityEvent`
  - Invalidate active sessions on email change (bump token_version)
  - Reference: [`R004`](../pentest/reports/R004-email-change-no-verification.md)
- [x] **R005 — Add `Secure` flag to `aspm_token` cookie**
  - Change `COOKIE_SECURE` default to `true` in config.go
  - Update `.env.example` to reflect the new default
  - The cookie already used `Secure` conditionally via `SetAuthCookie(secure bool)` — only the default changed
  - Reference: [`R005`](../pentest/reports/R005-cookie-missing-secure-flag.md)

---

## Completed (CHANGELOG audit ≤ v1.30.2)

Items that were open in the backlog but are already in production per [`HenKaiPan-self-hosted/CHANGELOG.md`](../HenKaiPan-self-hosted/CHANGELOG.md).

### UX & Platform

- [x] `GET /api/coverage`, badges, and filter on Projects — v1.20.0
- [x] Scanner Health Dashboard — v1.20.0
- [x] Scanner CI cache — v1.20.0
- [x] **Scheduled report delivery** (email/Slack) — v1.23.0 (`Report scheduling`: weekly/daily + email/slack channels)
- [x] **Per-token rate limiting** for API keys — token bucket in `APIKeyAuth` (60 req/min burst; see v1.29.0 rate limit package)
- [x] **SSRF validation on git targets** — v1.29.0 (allowlist + DNS; covers `repo_url` hardening in scans, not accessibility preflight)

### Instance & Distribution

- [x] **Backup script** (`scripts/backup.sh`) — v1.29.1 (step 1 of safe-update flow)
- [x] **Anonymous telemetry opt-out** — v1.28.0 (`HENKAIPAN_TELEMETRY_ENABLED`, daily ping to telemetry.dyallab.com.ar)
- [x] **Tier limits** + `GET /api/limits` — v1.28.0
- [x] **Auto-create project from GitHub Action** — v1.25.0 (part of CI/CD onboarding; wizard UI still pending)

### Testing & CI

- [x] Phases 0–3 — see Testing Infrastructure section
- [x] **`go test -race` in CI** — `ci-cd.yml` workflow (blocks build since v1.28.1)
- [x] **DB test approach documented** — `AGENTS.md` (testcontainers vs sqlmock decision)

### Observability

- [x] **pprof endpoints** (`ENABLE_PPROF`) — v1.22.0 (profiling infra; active optimization still pending)

---

## Backlog

*Last audit against CHANGELOG: 2026-06-27 · current release: v1.30.2*

### UX & Quality of Life

- [ ] `@username` mentions in comments → email notification

### Onboarding & Growth

- [ ] **GitHub-first onboarding wizard** (token or app-based UI flow) — *partial: auto-create v1.25.0, bulk import v1.6.0, docs CI/CD v1.8.0*
- [ ] Capture product analytics + feedback prompts — *distinct from anonymous telemetry v1.28.0*

### Instance Management

- [ ] Define self-hosted product boundary: what is included, what stays cloud-only, and why — *partial: MIT + cloud pricing v1.27.0, license removed v1.26.0*
- [ ] **Safe-Update Flow** documented end-to-end: DB Backup → Pull → Migrate → Restart — *backup script v1.29.1; missing unified operational guide*
- [ ] Data export/import strategy to support migration between cloud and self-hosted
- [ ] Support model definition for self-hosted customers (SLA, update cadence, installation support boundaries)

### Enterprise Features

- [x] OIDC SSO (single sign-on via OpenID Connect) — feature-flagged, env-var config, group-claim role mapping. See `docs/sso-authelia.md` for the Authelia + LLDAP guide.
- [ ] SAML SSO
- [ ] Multi-tenant support (organizations)
- [ ] **Advanced RBAC** (custom roles, granular permissions) — *partial: capability matrix v1.12.1, team-scoped access v1.29.0, datascope v1.30.2*
- [ ] Audit log export + SIEM integration

### Tech Debt

- [x] **SQL Injection Audit** — completed (see findings below)
  - [x] Audit all raw SQL queries (`db.Query`, `db.QueryRow`, `db.Exec`)
  - [x] Verify parameterized queries everywhere (no string concatenation)
  - [x] Check repository layer for dynamic query building
  - [x] Review migration files for any dynamic SQL patterns
  - [x] Scan for `fmt.Sprintf` used with SQL statements
  - **Findings**: 1 real injection risk fixed (`helpers.go:19` whitelist), 2 LIMIT/OFFSET parameterized (`notification.go:73`, `vulnerability_new.go:175`)
- [ ] **API versioning**: migrate remaining endpoints to `/api/v1/...` — *partial: external scans + tokens in v1.8.0*
  - [ ] Define migration strategy (co-locate `/api/` and `/api/v1/` during transition)
  - [ ] Migrate routes one by one (start with auth, then projects/scans/findings)
  - [ ] Update frontend to point to `/api/v1/`
  - [ ] Deprecate old `/api/` routes with `Deprecation` header
  - [ ] Rollback strategy
- [ ] **Inconsistent error messages**: ~200 message strings for same error codes — *partial: `{code, message}` format v1.12.0; incremental unification with API versioning*
- [ ] **Legacy repo terminology** in API/endpoints — migrate to "project" (operational note, no dedicated release)

### Testing Infrastructure

**Current state**: Phases 0–3 completed. `go test -race ./internal/...` runs in CI (`ci-cd.yml`). ~58% of packages have tests. Missing coverage gate and phases 4–8.

**Goal**: Establish sustainable testing patterns — pragmatic, not coverage-obsessed. Prioritize packages by risk/complexity.

**Established conventions to follow**:
- Package-local `_test.go` files (same package as code under test)
- `setupTest(t *testing.T)` helpers returning `(subject, ctx, cleanup)` closures
- `t.Helper()`, `defer cleanup()` pattern
- **No testify/assert** — per Go Wiki recommendations. Create minimal in-house `assert` helpers.
  - Rationale: [Go TestComments](https://go.dev/wiki/TestComments#assert-libraries) warns assert libs create a "new sub-language". [Alex Edwards](https://www.alexedwards.net/blog/the-9-go-test-assertions-i-use) proposes 9 custom helpers. [Anton](https://antonz.org/do-not-testify/) reduces to 3 (`AssertEqual[T]`, `AssertErr`, `AssertTrue`).
  - Approach: small, focused `internal/assert` package with 3-9 helpers. No external dep.
- `miniredis` already available (indirect dep) for Redis-dependent tests
- Test naming: `Test<Method>_<Scenario>`

- [x] **Phase 0 — Foundation** ✅
  - [x] Create `internal/assert/` package with custom assertion helpers (~100-150 lines)
    - `assert.Equal[T]`, `assert.NotEqual[T]`, `assert.Nil`, `assert.NotNil` — equality
    - `assert.True`, `assert.False` — boolean
    - `assert.ErrorIs`, `assert.ErrorAs` — error semantics
    - `assert.MatchesRegexp` — string patterns
  - [x] Create `make test` target: `go test ./internal/...` with race detection
  - [x] Create `make test-coverage` target with HTML output
  - [x] Optional: `make test-integration` for future DB-backed tests
  - [x] `internal/testhelpers/` package created (removed in v1.30.0 — dead code)

- [x] **Phase 1 — Pure logic packages (no I/O, easy wins)** ✅
  - [x] `vulnerability/`: `ComputeVulnUID`, `NormalizePath`, `NormalizeVersion`, `EngineTypeFromCategory`
  - [x] `auth/`: `IssueToken`, `ValidateToken`, `GetClaims`, role check logic
  - [x] `secrets/`: `Encrypt`/`Decrypt` roundtrip, key mismatch, empty input
  - [x] `webhook/`: `SignPayload`/`VerifySignature`, `IsWithinTimeWindow`, timestamp edge cases
  - [x] `pagination/`: `FromQuery`, `Normalize`, defaults, boundary values
  - [x] `validation/`: `ValidateStruct`, custom validators, error formatting
  - [x] `config/`: `Load()` with various env var combinations, missing required vars, defaults
  - [x] `license/`: Claims validation, expiration edge cases, tampered signatures (removed in v1.26.0)
  - [x] `logger/`: Init with different formats/dev modes

- [x] **Phase 2 — Parser packages (fixture-based)** ✅
  - [x] `scanner/parsers`: `ParseSARIF`, `ParseGrype`, `ParseOSV`, `ParseTrufflehog`, `ParseGitleaks`, `ParseCheckov`, `ParseKICS`, `ParseNuclei`
    - [x] Collect sample output files (one per scanner) into `internal/scanner/testdata/`
  - [x] `scanner/registry`: `ResolvePack`, `CategoryFor`, `Get`, `ListInfo`, `CheckBinaryAvailability`
  - [x] `knowledge/`: `Slugify`, article builder functions
  - [x] `findings/`: prompt construction, agent input/output validation

- [x] **Phase 3 — Redis-dependent packages (via miniredis)** ✅
  - [x] `events/`: `Hub` publish/subscribe, `Client` connect/disconnect, broadcast edge cases
  - [x] `queue/`: Asynq `NewClient`/`NewServer` config validation, payload enqueue
  - [x] `ratelimit/`: Expand existing tests — configurable rates, cleanup/expiry edge cases
  - [x] `middleware/`: `RateLimiter` middleware hookup, `RequireOwnership` logic, `SecurityHeaders` presence

- [ ] **Phase 4 — Repository layer (DB-backed)**
  - **Largest surface**: 23 files, 16 interfaces, 75+ exported symbols. Highest risk for regressions.
  - Approach: testcontainers-go with real PG (documented in `AGENTS.md`)
  - [x] Decide approach and document in `AGENTS.md`
  - [ ] Create shared test DB bootstrap (e.g. `internal/testdb/` package)
  - [ ] Implement tests per repository interface:
    - [ ] `Stores` (core container struct)
    - [ ] `AppRepository`, `ProjectRepository`, `ScanRepository`, `FindingRepository`
    - [ ] `UserRepository`, `TeamRepository`, `TokenRepository`
    - [ ] `VulnerabilityRepository`, `MetricsRepository`
    - [ ] `PolicyRepository`, `RiskAcceptanceRepository`, `NotificationRepository`
    - [ ] `AuditRepository`, `WebhookRepository`, `SettingsRepository`
    - [ ] `HealthRepository`, `AgentRepository`, `ScheduleRepository`, `KnowledgeRepository`
  - [ ] `db/`: `Connect` edge cases, `RunMigrations` idempotency, `EnsureAdminUser`

- [ ] **Phase 5 — HTTP handlers (integration)**
  - **2nd largest package**: 31 files. All request routing, auth, error mapping.
  - Use `net/http/httptest` + chi test helpers.
  - [ ] Create shared test server — chi router with mock stores, test JWT seed
  - [ ] Auth + middleware integration:
    - [ ] `JWTMiddleware`: valid/invalid/expired tokens, missing header
    - [ ] `RequireRole`: admin vs user access, missing role
    - [ ] `RequireOwnership`: own vs other's resource
  - [ ] Handler tests (happy path + error cases):
    - [ ] Health endpoint
    - [ ] Auth handlers (login, register, refresh)
    - [ ] Project CRUD
    - [ ] Scan lifecycle (create, list, get, cancel)
    - [ ] Finding listing, detail, status update
    - [ ] Vulnerability listing, detail, correlation
    - [ ] App CRUD, project membership
    - [ ] Policy CRUD, evaluation
    - [ ] Team/user management
    - [ ] Notification settings, webhook config
    - [ ] API token management
    - [ ] Knowledge articles
    - [ ] Metrics/stats endpoints
    - [ ] MCP endpoint
  - [ ] `httperrors/`: Expand existing tests — `Wrap`, `New`, all status code helpers

- [ ] **Phase 6 — Task handlers (Asynq workers)**
  - Complex: need Asynq server testability or handler-level testing.
  - [ ] `tasks/`:
    - [ ] `HandleScan`: payload parsing, scanner dispatch, status update
    - [ ] `HandleFindingSummarize` / `HandleFindingValidate`: prompt building, result handling
    - [ ] `HandleWebhookSend` / `HandleEmailSend`: payload routing, delivery
    - [ ] `HandleDigestSend`: aggregation, scheduling
    - [ ] Schedulers: `StartWeeklyDigestScheduler`, `StartScanScheduler`, `StartSLABreachMonitor`
  - [ ] `ai/`: Provider dispatch (Cloudflare vs OpenRouter vs Ollama), request building, response parsing
  - [ ] `github/`: `ValidateToken`, `ResolvePattern`, `RepoInfo`
  - [ ] `jira/`: `NewClient`, `CreateIssueRequest`/`Response` serialization

- [ ] **Phase 7 — CI integration & coverage gates**
  - [x] Run tests in CI — `go test -race -count=1 ./internal/...` in `ci-cd.yml` (v1.28.1+)
  - [ ] Set coverage floor (start at 20%, increase over time)
  - [ ] Expand `AGENTS.md` with full test conventions (beyond DB approach)
  - [ ] Optional: dedicated `make test-race` target mirroring CI

- [ ] **Phase 8 — Stress & concurrency tests**
  - [ ] Concurrent scan dispatch correctness
  - [ ] Rate limiter concurrent safety (already started)
  - [ ] Event hub concurrent pub/sub
  - [ ] Repository concurrent access (DB isolation levels)

### Scanner Extensions

- [ ] **Dependency Inventory Sync**: Parse manifests (package-lock.json, go.mod, Cargo.lock, requirements.txt, poetry.lock, pom.xml, etc.) from connected repos → normalize (ecosystem, name, version, source_file) → persist in `project_dependencies` → batch query OSV `/v1/query` to detect vulns without a prior SCA scan. Independent of SBOM; prerequisite for proactive threat intel matching.
- [ ] SBOM generation and tracking
- [ ] Custom scanner plugins (community-contributed scanners with standardized interface)
- [ ] **Scanner Marketplace** (long-term) — discovery, install, and cross-correlation of third-party scanners; requires standardized plugin contract, sandboxed execution, and contribution guidelines

### Threat Intelligence & Proactive Exposure *(in design — see detailed discussion)*

Vision: **ingest industry threats** (new CVEs, KEV, GHSA/OSV) and cross-reference them against the **dependency inventory** (via Dependency Inventory Sync) and **existing scan findings**. On match, **report impact** and optionally **trigger targeted scans**. Does not require SBOM as a prerequisite — inventory sync + OSV batch covers the initial gap.

**Two orthogonal tracks:**

| Track | Question | Evidence | Sources |
|-------|----------|-----------|---------|
| **Track 1 — Inventory (Posture)** | Do we have it? | `declared` → `detected` → `corroborated` | Inventory sync, SCA findings, container scans, SBOM |
| **Track 2 — Runtime (Risk)** | Is it exploitable? | `L0` no deployed → `L1` not reachable → `L2` exploitable → `L3` active exploitation → `L4` compromised | Nuclei CVE templates, KEV overlay, SIEM integration |

- **Explicit evidence states** (no fuzzy scores): `declared` (manifest), `detected` (scanner), `corroborated` (2+ sources), `exploitable` (DAST/Nuclei positive), `active_threat` (KEV + any of the above)
- **Verify-first**: match by package name without CVE → silent rescan, don't show in UI until confirmed
- **KEV overlay first-class**: `is_kev` flag → red badge, priority notification, differentiated alert flow
- **Dual badge UI**: inventory_status + runtime_status per advisory, visible in table and detail view

**Components:**

- [ ] **Dependency Inventory Sync**: see Scanner Extensions (prerequisite)
- [ ] **Configurable threat intel feed**: periodic ingest from opt-in sources — CISA KEV (public API, no key), OSV API (`/v1/query` bulk), NVD (phase 2, rate limits + heavier CPE matching) — with dedup by `cve_id` / GHSA / source+external_id
- [ ] **Threat advisory entity**: `threat_advisories` table with external_id, source, cve_id, title, severity, cvss_score, is_kev, affected_json (packages/CPE), published_at, raw_json
- [ ] **Track 1 — Inventory matching**:
  - [ ] Match by exact `cve_id` in `vulnerabilities`/`findings` (evidence: `detected`)
  - [ ] Match by package@version against `project_dependencies` (evidence: `declared`)
  - [ ] Corroborated match (2+ sources) → evidence: `corroborated`
  - [ ] Silent rescan for unconfirmed matches (verify-first)
  - [ ] KEV overlay: KEV advisory + any match → `active_threat`
- [ ] **Track 2 — Runtime assessment**:
  - [ ] L0–L4 levels per project+advisory, with promotion rules
  - [ ] Nuclei CVE template against `runtime_url` when there's an inventory hit
  - [ ] KEV + L2 → urgent notification (active exploitation)
  - [ ] L4 requires external integration (SIEM webhook, manual report)
- [ ] **Exposure report**: “Threats affecting us” view/API — both tracks visible, filter by track/status, link to vuln/project
- [ ] **Automatic response (opt-in)**:
  - [ ] On new match → notification (email/Slack/webhook) + advisory linked to project
  - [ ] Enqueue **targeted scan** — Trivy/Grype repo rescan, `trivy-image` on known images, Nuclei with `-t CVE-YYYY-NNNN` against `runtime_url` — reuse `scan_schedules` + worker, no new pipeline
  - [ ] Policy by severity and track: alert vs auto-scan vs auto-scan + SLA breach
- [ ] **Integration with Full-Scan Validation Pipeline**: threat match in SCA → chain PoC/DAST to confirm runtime exploitability (see next section)

**Implementation phases:**

| Phase | What | Dependencies | Value |
|-------|------|-------------|-------|
| F1 | Dependency Inventory Sync + OSV batch query | Connected repos | Detect vulns without prior scan |
| F2 | Threat feed (KEV+OSV) + Track 1 matching | F1 + `vulnerabilities.cve_id` index | "Does it affect us?" by inventory |
| F3 | `runtime_url` on projects + targeted Nuclei CVE + Track 2 L0–L2 | F2, projects.runtime_url | "Is it exploitable?" |
| F4 | KEV overlay + dual badge UI | F3 | Visual prioritization + urgent notification |
| F5 | SIEM/webhook integration for L4 + evidence dashboard | F4 | "Are we compromised?" |

**Concrete MVP (F1+F2, ~3-4 weeks dev):**
1. Migration: `project_dependencies` + `threat_advisories` + `project_inventory_hits`
2. Manifest parser + OSV batch query worker
3. CISA KEV fetcher + exact CVE matcher
4. 6h scheduler (same pattern as `StartSLABreachMonitor`)
5. API `GET /api/threats/exposures` + "Affecting us" dashboard
6. Webhook/email notification for `active_threat`

### Full-Scan Validation Pipeline *(idea — build + runtime)*

Vision: a **chained full scan** — static analysis output doesn't stay as an isolated alert; actionable context is derived and **dynamically confirmed** at build (CI/staging) and at runtime (deployed environment). Complements the existing cross-scanner correlation (v1.16–v1.17) with **exploitability validation**. Pairs with **Threat Intelligence** when the threat comes from outside (industry) rather than from a scan.

- [ ] **SAST → DAST chain**: From SAST findings (semgrep, gosec, checkov, etc.), extract attack surface (routes, parameters, sinks) and enqueue DAST (nuclei or other) against configurable targets — validate in **build** (preview/CI) and in **runtime** (prod/staging)
- [ ] **SCA → exploitability → PoC/DAST chain**: From CVE/GHSA in SCA, assess reachability and known exploit method; generate or select PoC/check template and confirm via DAST or dedicated exploit scanner
- [ ] **Validation status on vulnerability**: Extend the model (`vulnerabilities`) with confirmation evidence — e.g. `validated_build`, `validated_runtime`, `poc_attempted`, `exploit_confirmed` — linking SAST/SCA findings with DAST/PoC evidence on the same canonical row. Aligns with Threat Intel Track 2 evidence states (`L0–L4`).
- [ ] **Worker orchestration**: Staged pipeline — static scan completes → enrich context → trigger validation scan (no blind re-scan; payload with targets derived from the parent finding)
- [ ] **Build vs runtime targets**: Per-project/app config — CI/preview URL vs runtime URL (`runtime_url` for Threat Intel Track 2); policy on which validations run in each phase and when to block merge vs just alert
- [ ] **Evidence chain UI**: On finding/vuln detail, show the full chain (SAST → hypothesis → DAST/PoC → confirmed/rejected) with timestamps and environment where validated. Integrate Threat Intel dual badge UI (inventory_status + runtime_status) when applicable.

### CI/CD & API Security

- [ ] Token rotation endpoint (optional)
- [ ] **Preflight `repo_url` accessibility** before enqueuing external scans — *distinct from SSRF allowlist v1.29.0 (verify the repo is reachable/cloneable)*

### Platform Health

- [ ] Queue monitoring dashboard (Asynq metrics) — *Prometheus queue collector v1.1.0; missing UI*
- [ ] Active performance optimization pass — *pprof infra v1.22.0; profiling ≠ optimization*

### Workflow Enhancements

- [ ] Finding templates (pre-defined triage workflows)
- [ ] Automated assignment rules beyond existing policies — *auto-triage v1.0.0; ad-hoc rules pending*
- [ ] SLA customization per project/app — *SLA tracking global v1.0.0*
- [ ] Custom fields on findings

### Reporting & Compliance

- [ ] Custom report templates — *scheduled delivery v1.23.0; custom templates pending*
- [ ] Compliance evidence collection automation
- [ ] Vendor risk assessment module

---

## Notes

- **Scanner execution**: Scanners run as binaries via `os/exec` in the worker process — no Docker socket, no container isolation per scan (v1.5.0)
- **Repos page**: Legacy, removed v1.13.0 — superseded by Projects
- **Legacy repo references**: Some API endpoints still use "repo" terminology — migrate to "project" (backlog Tech Debt)
- **PDF reports**: Browser print stylesheet exists, verify it works correctly
- **Credibility UI**: Complete — v1.16.0 (badges, sorting, corroborating scanner names, correlation reasons)
- **pnpm 11**: Frontend Docker build requires `--ignore-scripts` + explicit `pnpm rebuild esbuild sharp` (v1.5.1)

---

*Last updated: 2026-06-28*
