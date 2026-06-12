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

**Current release:** v1.23.0 (2026-06-11)
**Next planned:** v1.24.0

### Completed Releases (summary)

| Version | Key Changes |
|---------|-------------|
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

## 🔜 v1.24.0 — Planned

Focus: **SMB workflow & visibility** — bulk actions, Slack bot, onboarding flow.

- [ ] **Bulk Findings Actions**: multi-select findings → batch status change / assign / dismiss — UI-only, backend already supports PATCH
- [ ] **Slack Interactive Bot**: Slack Socket Mode bot for triage (acknowledge, dismiss, assign) directly from Slack — interactive buttons via Block Kit

---

## Backlog

### UX & Quality of Life

- [x] `GET /api/coverage` — scan coverage report (projects without scans in last N days)
- [x] Projects page badges: "Never scanned" / "Last scan: X days ago"
- [x] Projects filter: "Show only projects without recent scans"
- [ ] `@username` mentions in comments → email notification

### Onboarding & Growth

- [ ] GitHub-first onboarding flow (token or app-based), optimized for small teams
- [ ] Capture product analytics + feedback prompts
- [ ] Define packaging/limits for early plans (cloud vs self-hosted)
- [ ] Billing readiness for cloud plans

### Instance Management

- [ ] Define self-hosted product boundary: what is included, what stays cloud-only, and why
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

- [x] **SQL Injection Audit**: review all raw SQL queries for injection vulnerabilities
  - [x] Audit all raw SQL queries (`db.Query`, `db.QueryRow`, `db.Exec`)
  - [x] Verify parameterized queries everywhere (no string concatenation)
  - [x] Check repository layer for dynamic query building
  - [x] Review migration files for any dynamic SQL patterns
  - [x] Scan for `fmt.Sprintf` used with SQL statements
  - **Findings**: 1 real injection risk fixed (`helpers.go:19` whitelist), 2 LIMIT/OFFSET parameterized (`notification.go:73`, `vulnerability_new.go:175`)
- [ ] **API versioning**: migrate existing endpoints to `/api/v1/...` with deprecation strategy
  - [ ] Define migration strategy (co-locate `/api/` and `/api/v1/` during transition)
  - [ ] Migrate routes one by one (start with auth, then projects/scans/findings)
  - [ ] Update frontend to point to `/api/v1/`
  - [ ] Deprecate old `/api/` routes with `Deprecation` header
  - [ ] Rollback strategy
- [ ] **Inconsistent error messages**: ~200 message strings for same error codes. Frontend reads `code` field so non-blocking. Consider doing incrementally as part of API versioning migration.

### Testing Infrastructure

**Current state**: 26 packages under `internal/`, ~15 have tests (~58%). `internal/assert/` and `internal/testhelpers/` exist. `make test` target exists. No CI test step yet.

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
  - [x] Create `internal/testhelpers/` package: shared `NewMiniredis` helper, context factories, `TestLogger`

- [x] **Phase 1 — Pure logic packages (no I/O, easy wins)** ✅
  - [x] `vulnerability/`: `ComputeVulnUID`, `NormalizePath`, `NormalizeVersion`, `EngineTypeFromCategory`
  - [x] `auth/`: `IssueToken`, `ValidateToken`, `GetClaims`, role check logic
  - [x] `secrets/`: `Encrypt`/`Decrypt` roundtrip, key mismatch, empty input
  - [x] `webhook/`: `SignPayload`/`VerifySignature`, `IsWithinTimeWindow`, timestamp edge cases
  - [x] `pagination/`: `FromQuery`, `Normalize`, defaults, boundary values
  - [x] `validation/`: `ValidateStruct`, custom validators, error formatting
  - [x] `config/`: `Load()` with various env var combinations, missing required vars, defaults
  - [x] `license/`: Claims validation, expiration edge cases, tampered signatures
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
  - Approach options: A) testcontainers-go with real PG (most reliable), B) sqlmock (fastest), C) shared Docker PG (balanced)
  - [x] Decide approach and document in \`AGENTS.md\`
  - [ ] Create shared test DB bootstrap (`internal/testhelpers/testdb.go`)
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
  - [ ] Create shared test server (`internal/testhelpers/httptest.go`) — chi router with mock stores, test JWT seed
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
  - [ ] Add `make test` to CI workflow (GitHub Actions)
  - [ ] Set coverage floor (start at 20%, increase over time)
  - [ ] Add `make test-race` for race detection in CI
  - [ ] Document test conventions in `AGENTS.md`

- [ ] **Phase 8 — Stress & concurrency tests**
  - [ ] Concurrent scan dispatch correctness
  - [ ] Rate limiter concurrent safety (already started)
  - [ ] Event hub concurrent pub/sub
  - [ ] Repository concurrent access (DB isolation levels)

---
### Scanner Extensions

- [ ] SBOM generation and tracking
- [ ] Custom scanner plugins (community-contributed scanners with standardized interface)
- [ ] **Scanner Marketplace** (largo plazo) — discovery, install, and cross-correlation of third-party scanners; requires standardized plugin contract, sandboxed execution, and contribution guidelines

### CI/CD & API Security

- [ ] Per-token rate limiting for API tokens
- [ ] Token rotation endpoint (optional)
- [ ] Validate `repo_url` is accessible before enqueuing external scans

### Platform Health

- [x] Scanner Health Dashboard — failure rates, avg duration, success % table
- [ ] Queue monitoring dashboard (Asynq metrics)
- [ ] Performance profiling + optimization
- [x] **Cache scanners in CI**: Worker Docker build downloads all scanner binaries from scratch. Add GitHub Actions caching for downloaded tarballs to reduce build time from ~10min to <2min

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

*Última actualización: 2026-06-11*
