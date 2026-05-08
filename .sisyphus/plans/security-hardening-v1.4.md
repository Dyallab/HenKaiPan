# Security Hardening v1.4.0 — Work Plan

**Plan ID**: `plan_security_v1.4.0`  
**Generated**: 2026-05-08  
**Session**: `ses_prometheus_001`  
**Status**: DRAFT — Awaiting user approval

---

## Executive Summary

Transform HenKaiPan from "functional but insecure" to "production-hardened" by addressing 8 critical security gaps across infrastructure, API, and frontend layers. This plan follows defense-in-depth principles.

**Scope**: API, Worker, Frontend, Docker Compose, Kubernetes manifests  
**Out of Scope**: SAML/SSO (backlog), Multi-tenant support (backlog)

---

## Gap Analysis (Auto-Resolved)

| # | Gap | Severity | Location | Fix Approach |
|---|-----|----------|----------|---------------|
| G1 | Docker socket mount = root access | CRITICAL | worker.yaml, compose | Replace Docker SDK with os/exec + scanner binaries |
| G2 | IDOR: No ownership checks on any endpoint | CRITICAL | All `{id}` handlers | Ownership middleware + repository query updates |
| G3 | No input validation (frontend + backend) | HIGH | All handlers, api.ts | Zod schemas + go-playground/validator |
| G4 | Error details leaked in responses | HIGH | httperrors/errors.go | Sanitize error details, log internally |
| G5 | Missing security headers | MEDIUM | main.go router | Security headers middleware |
| G6 | JWT default secret + manual expiration | MEDIUM | auth/jwt.go | Remove default, use jwt.WithExpirationRequired() |
| G7 | Rate limiting fails open, no user ID | MEDIUM | middleware/ratelimit.go | Fix getUserID, fail-closed on Redis down |
| G8 | Compose zero hardening | MEDIUM | docker-compose.yml | cap_drop ALL, security_opt, no-new-privileges |
| G9 | K8s socket mount bypasses securityContext | MEDIUM | kubernetes/worker.yaml | Remove socket mount, update securityContext |

---

## Parallel Execution Waves

### Wave 1: Foundation (All tasks can run in PARALLEL)

#### T1: Error Sanitization [backend]
**Prompt**: 
```
TASK: Sanitize HTTP error responses to prevent information leakage.

MUST DO:
- Modify `internal/httperrors/errors.go` MapError function
- In production mode (check env var PRODUCTION=true), return generic messages without err.Error()
- Keep full error details in internal logs only (slog.ErrorContext)
- Update writeHTTPError to accept an optional "showDetails" flag based on environment
- Ensure SQL errors, connection strings, table names are NEVER exposed to API consumers
- Test: Create a test that verifies error response doesn't contain "pgx" or table names

MUST NOT DO:
- Delete or break existing HTTPError struct
- Change error codes (ErrInternal, ErrNotFound, etc.)
- Remove logging entirely

EXPECTED OUTCOME: 
- Production responses contain only: {"code": "internal_error", "message": "An internal error occurred"}
- Development responses can contain details
- All internal errors still logged via slog

CONTEXT:
- File: internal/httperrors/errors.go
- Error codes defined at lines 9-20
- MapError function at lines 91-117 currently includes err.Error() in all responses
```

#### T2: JWT Hardening [backend]
**Prompt**:
```
TASK: Harden JWT implementation to remove insecure defaults.

MUST DO:
- Remove hardcoded `var secret = "dev-secret"` from internal/auth/jwt.go line 13
- Make the secret variable unexported and require SetSecret() to be called before any JWT operations
- Add panic or fatal exit if Parse or IssueToken is called before SetSecret()
- Replace manual expiration check (lines 176-181) with jwt.WithExpirationRequired() option in jwt.Parse()
- Update jwt.Parse call to: jwt.Parse(tokenStr, keyFunc, jwt.WithExpirationRequired())
- Ensure SameSite cookie setting is properly validated (already in parseSameSite, verify it's used)

MUST NOT DO:
- Change the JWT claims structure (sub, role, user_id, exp)
- Break existing token validation logic
- Remove SetSecret() function

EXPECTED OUTCOME:
- No default secret exists
- Expired tokens are rejected by the jwt library itself
- Calling IssueToken before SetSecret causes immediate error

CONTEXT:
- File: internal/auth/jwt.go
- SetSecret called in cmd/api/main.go line 34
- JWT middleware at lines 42-62
```

#### T3: Security Headers Middleware [backend]
**Prompt**:
```
TASK: Add security headers middleware to all API responses.

MUST DO:
- Create new file internal/middleware/security_headers.go
- Implement middleware that sets:
  - Content-Security-Policy: "default-src 'self'" (allow unsafe-inline for Astro dev mode detection)
  - X-Content-Type-Options: "nosniff"
  - X-Frame-Options: "DENY"
  - X-XSS-Protection: "1; mode=block"
  - Strict-Transport-Security: "max-age=31536000; includeSubDomains" (only if cfg.CookieSecure is true)
- Register middleware in cmd/api/main.go AFTER chi middleware but BEFORE routes
- Make headers configurable via config if needed (optional, can hardcode safe defaults)

MUST NOT DO:
- Override CORS headers set by cors middleware
- Set CSP that breaks the Astro frontend
- Add headers to /api/health or /metrics endpoints (skip them)

EXPECTED OUTCOME:
- All API responses include security headers
- Headers visible in browser DevTools Network tab
- CSP allows frontend at localhost:4321 to function

CONTEXT:
- Router setup in cmd/api/main.go lines 116-121
- CORS config at lines 303-308
- Config has CookieSecure field at internal/config/config.go line 28
```

#### T4: Rate Limiting Fixes [backend]
**Prompt**:
```
TASK: Fix rate limiting to use user ID and fail-closed on Redis errors.

MUST DO:
- Implement getUserID() in internal/middleware/ratelimit.go (currently stub at lines 151-155)
- Extract user ID from JWT claims in request context (claims stored by auth.JWTMiddleware)
- Update checkRateLimit(): if Redis fails, return FALSE (fail-closed) instead of true
- Add configuration option for fail-open vs fail-closed (default: fail-closed for security)
- Log Redis connection errors with high severity
- Update rate limit headers to include X-RateLimit-User if user ID is available

MUST NOT DO:
- Remove IP-based fallback entirely (keep as fallback for unauthenticated endpoints)
- Change the Redis key structure (ratelimit:auth:, ratelimit:heavy:, ratelimit:general:)
- Break existing rate limit logic for auth endpoints

EXPECTED OUTCOME:
- Authenticated requests rate-limited by user ID
- Redis down = requests blocked (not allowed through)
- Rate limit headers properly set on all responses

CONTEXT:
- File: internal/middleware/ratelimit.go
- getUserID stub at lines 151-155
- JWT claims stored in context at internal/auth/jwt.go line 59
- Claims struct at internal/auth/jwt.go lines 24-29
```

#### T5: Input Validation Setup [backend + frontend]
**Prompt**:
```
TASK: Set up input validation infrastructure for frontend (Zod) and backend (go-playground/validator).

MUST DO:
- BACKEND: Add github.com/go-playground/validator/v10 to go.mod
- Create internal/validation/validator.go with helper functions
- Define validation structs for all API request bodies (LoginRequest, CreateProjectRequest, UpdateFindingRequest, etc.)
- FRONTEND: Add zod to frontend/package.json
- Create frontend/src/lib/validators.ts with Zod schemas matching backend structs
- Export TypeScript types inferred from Zod schemas
- Ensure validators cover: required fields, string lengths, URL formats, UUID formats, enum values

MUST NOT DO:
- Change existing API handler signatures
- Break existing frontend API calls
- Add validation that rejects currently valid inputs

EXPECTED OUTCOME:
- Backend has validator package integrated
- Frontend has Zod integrated
- Validation structs/schemas created but NOT yet applied (that's Wave 3)
- Types are synchronized between frontend and backend

CONTEXT:
- Backend go.mod at root
- Frontend package.json at frontend/package.json
- API handlers in internal/handlers/ (scan handlers, project handlers, etc.)
- Frontend API client at frontend/src/lib/api.ts
```

#### T6: Docker Compose Hardening [infrastructure]
**Prompt**:
```
TASK: Harden docker-compose.yml with security best practices.

MUST DO:
- Add to ALL services (api, worker, postgres, redis):
  - security_opt:
      - no-new-privileges:true
  - cap_drop:
      - ALL
- Add to api and worker services:
  - cap_add: [] (empty, no capabilities added back)
  - read_only: true (if possible, test that app still works)
  - tmpfs: /tmp (if read_only is true)
- Remove /var/run/docker.sock mount from worker (prepare for Wave 2 T9)
- Add comments explaining each security option
- Test: `docker compose up` should still work

MUST NOT DO:
- Change container images
- Change port mappings
- Remove healthchecks
- Break the application functionality

EXPECTED OUTCOME:
- docker-compose.yml passes docker-compose config validation
- All services have cap_drop ALL
- Worker socket mount removed (or commented out with TODO)
- Security options documented

CONTEXT:
- File: HenKaiPan-self-hosted/docker-compose.yml
- Current worker mount at line 91
- Security context examples in HenKaiPan-self-hosted/kubernetes/worker.yaml
```

#### T7: Kubernetes Hardening [infrastructure]
**Prompt**:
```
TASK: Remove docker socket mount from Kubernetes worker and enhance securityContext.

MUST DO:
- Remove docker-sock volume and volumeMount from HenKaiPan-self-hosted/kubernetes/worker.yaml
- Keep allowPrivilegeEscalation: false (already set)
- Keep runAsNonRoot: true (already set)
- Keep capabilities drop: [ALL] (already set)
- Add: readOnlyRootFilesystem: true to container securityContext
- Add: runAsGroup: 1000 (match runAsUser)
- Remove hostPath volume for docker-sock entirely
- Update comments to explain security posture
- Create a note that worker image will be updated in Wave 2

MUST NOT DO:
- Change replica count
- Change image pull policy
- Break existing securityContext settings

EXPECTED OUTCOME:
- worker.yaml has no docker socket references
- Security context is enhanced with readOnlyRootFilesystem
- File passes kubectl validation

CONTEXT:
- File: HenKaiPan-self-hosted/kubernetes/worker.yaml
- Socket mount at lines 29-31 and volume at lines 48-52
- API yaml at HenKaiPan-self-hosted/kubernetes/api.yaml for reference
```

---

### Wave 2: Core Changes (Depends on Wave 1)

#### T8: IDOR Ownership Middleware [backend] — Depends on T2 (JWT Hardening)
**Prompt**:
```
TASK: Create ownership validation middleware to prevent IDOR attacks.

MUST DO:
- Create internal/middleware/ownership.go
- Implement middleware factory: RequireOwnership(resourceType string, getResourceID func(r *http.Request) string)
- Middleware flow:
  1. Extract user ID from JWT claims (same as auth.GetClaims)
  2. Extract resource ID from URL (e.g., projectID, id)
  3. Query database to verify user owns the resource OR belongs to the resource's team
  4. For projects: check projects.app_id -> apps.team_id -> team_members.user_id
  5. For apps: check apps.team_id -> team_members.user_id
  6. For scans/findings: check via project_id join
  7. If no ownership: return 403 Forbidden with standardized error
  8. If owned: inject resource into context, call next handler
- Add helper functions for common ownership checks (CheckProjectOwnership, CheckAppOwnership)
- Create internal/repository/ownership.go with SQL queries for ownership checks

MUST NOT DO:
- Break existing auth.JWTMiddleware chain
- Add ownership checks to /api/health, /api/version, /api/auth/* endpoints
- Make database queries that are vulnerable to SQL injection

EXPECTED OUTCOME:
- Middleware can be applied to any endpoint with a resource ID
- Ownership verified before handler executes
- 403 returned for unauthorized access attempts
- Queries are efficient (use indexes on id, team_id, user_id)

CONTEXT:
- JWT claims extraction: internal/auth/jwt.go GetClaims() function
- Database schema: projects have app_id, apps have team_id, team_members links users to teams
- Repository pattern: internal/repository/ with Stores struct
- Example query pattern in internal/repository/projects.go
```

#### T9: Scanner Binary Execution Engine [backend] — Standalone (biggest task)
**Prompt**:
```
TASK: Replace Docker SDK scanner execution with direct binary execution using os/exec.

MUST DO:
- Identify all Docker SDK usage in internal/scanner/ directory
- Create new file internal/scanner/executor.go with interface:
  type ScannerExecutor interface {
    RunScanner(ctx context.Context, scannerType string, target string) ([]Finding, error)
  }
- Implement executor for each scanner:
  - Semgrep: exec.Command("semgrep", "--json", "--config=auto", target)
  - Trivy: exec.Command("trivy", "fs", "--format", "json", target)
  - Gitleaks: exec.Command("gitleaks", "detect", "--report-format", "json", "--source", target)
  - Checkov: exec.Command("checkov", "--directory", target, "--output", "json")
  - Others: map existing Docker-based scanners to binary equivalents
- Parse JSON output from each scanner into internal models
- Handle scanner not found (binary missing) with clear error message
- Set timeout for scanner execution (reuse existing 30min timeout concept)
- Update internal/scanner/registry.go to use new executor instead of Docker client
- Remove github.com/docker/docker dependency from go.mod (if only used for scanners)

MUST NOT DO:
- Break existing scan job flow (scan:run in Asynq)
- Change Finding model structure
- Remove ability to scan (must maintain feature parity)
- Keep Docker SDK code (delete it)

EXPECTED OUTCOME:
- Scanners run as binaries via os/exec
- No Docker socket or Docker SDK needed
- JSON output properly parsed into findings
- Timeout and error handling maintained
- Worker can run without /var/run/docker.sock

CONTEXT:
- Scanner registry: internal/scanner/registry.go
- Docker usage likely in internal/scanner/ or internal/worker/ packages
- Asynq job handler: cmd/worker/main.go
- Scanner packs defined in AGENTS.md: sast, sca, secrets, iac, containers
- Need to handle the case where binary is not installed (graceful degradation)
```

---

### Wave 3: Integration (Depends on Wave 2)

#### T10: Apply IDOR Middleware to All Handlers [backend] — Depends on T8
**Prompt**:
```
TASK: Apply ownership middleware to all API endpoints with resource IDs.

MUST DO:
- Update cmd/api/main.go to wrap handlers with ownership middleware:
  - /api/projects/{projectID}: Use RequireOwnership("project", extractProjectID)
  - /api/apps/{id}: Use RequireOwnership("app", extractAppID)
  - /api/scans/{id}: Use RequireOwnership("scan", extractScanID) (check via project)
  - /api/findings/{id}: Use RequireOwnership("finding", extractFindingID) (check via scan->project)
  - /api/risk-acceptances/{id}: Use RequireOwnership("risk-acceptance", ...)
  - Continue for ALL endpoints with {id} or {projectID} parameters
- Helper to extract IDs from chi URL parameters: chi.URLParam(r, "id")
- Test with authenticated user trying to access another user's resources
- Ensure admin role can still access all resources (modify middleware to skip check for admin)
- Update handler functions to use resource from context (if needed) instead of re-querying

MUST NOT DO:
- Break unauthenticated endpoints (/api/auth/login, /api/health, /api/version)
- Add middleware to webhook endpoints (use webhook secret instead)
- Change the order of middleware chain (JWT first, then ownership)

EXPECTED OUTCOME:
- All resource endpoints protected by ownership checks
- IDOR attacks blocked (403 Forbidden)
- Admin users can still access all resources
- No regression in existing functionality

CONTEXT:
- Router setup: cmd/api/main.go lines 116-296
- chi URL parameters: chi.URLParam(r, "id")
- Auth middleware: auth.JWTMiddleware
- Role checking: auth.RequireRole() at internal/auth/jwt.go line 112
```

#### T11: Worker Multi-Stage Build with Scanner Binaries [infrastructure] — Depends on T9
**Prompt**:
```
TASK: Create multi-stage Dockerfile for worker that includes scanner binaries.

MUST DO:
- Create or update docker/worker/Dockerfile (or Dockerfile.worker at root)
- Multi-stage build:
  Stage 1 (builder): golang:1.2x-alpine to compile worker binary
  Stage 2 (scanners): alpine base to install scanner binaries:
    - apk add --no-cache curl bash git
    - Install semgrep: pip install semgrep (or binary release)
    - Install trivy: curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
    - Install gitleaks: download from GitHub releases
    - Install checkov: pip install checkov
    - Add any other scanners from scanner packs (grype, gosec, trufflehog, nuclei)
  Stage 3 (final): alpine minimal with:
    - Copied worker binary from builder
    - Copied scanner binaries from scanners stage
    - USER 1000:1000 (non-root)
    - No shell, no package manager in final stage (minimal attack surface)
- Update .dockerignore to exclude unnecessary files
- Document image size estimate in comments
- Test: docker build completes, binary runs, scanners execute

MUST NOT DO:
- Include Docker CLI or Docker daemon in final image
- Run as root in final image
- Include source code or build tools in final image
- Make image larger than necessary (use multi-stage properly)

EXPECTED OUTCOME:
- Worker image has all scanner binaries included
- Image runs as non-root user
- No Docker socket needed
- Image size increase reasonable (~300-500MB for all scanners)

CONTEXT:
- Current worker image: ghcr.io/dyallab/henkaipan-worker:latest
- Scanner list: semgrep, trivy, gitleaks, checkov, grype, gosec, trufflehog, nuclei
- Worker entrypoint: cmd/worker/main.go
- Need to ensure binary architecture matches (amd64 vs arm64)
```

#### T12: Apply Input Validation to All Handlers [backend + frontend] — Depends on T5
**Prompt**:
```
TASK: Apply input validation to all API handlers and frontend forms.

MUST DO:
- BACKEND: Update all API handlers to validate input:
  - Login: validate username (email format), password (min length)
  - CreateProject: validate name (required, max 255), description (max 1000), repo_url (valid URL or empty)
  - UpdateFinding: validate status (enum: open|in_review|accepted_risk|fixed|verified), notes (max 5000)
  - CreateScan: validate project_id (UUID format), scanner_type (enum)
  - BulkUpdateFindings: validate array of IDs, status
  - ALL PATCH/POST handlers need validation
  - Use validator.Struct() and return 400 with validation errors in response
  - Format validation errors as: {"code": "validation_error", "message": "Validation failed", "details": {"field": "error"}}
- FRONTEND: Apply Zod schemas to all forms:
  - Login form: validate email, password
  - Create Project form: validate name, URL
  - Finding update modal: validate notes, status
  - Export form: validate filters
  - Show validation errors in UI (red borders, error messages)

MUST NOT DO:
- Break existing API responses
- Change API endpoint signatures
- Make validation so strict that it rejects valid historical data
- Forget to validate bulk operations (array inputs)

EXPECTED OUTCOME:
- All API inputs validated before processing
- Frontend shows validation errors immediately
- Invalid inputs return 400 with clear error messages
- Valid inputs continue to work as before

CONTEXT:
- Backend validation structs to be created in T5
- Frontend Zod schemas to be created in T5
- API handlers in internal/handlers/
- Frontend forms in frontend/src/pages/ and components
- Error format: internal/httperrors/errors.go
```

---

### Wave 4: Verification (Standard)

#### F1: Build Verification
- [ ] `make build` passes with no errors
- [ ] `go mod tidy` (no unused dependencies)
- [ ] Scanner binaries not in API image (only worker)
- [ ] All services start with `make up`

#### F2: Security Verification
- [ ] IDOR test: User A cannot access User B's projects (expect 403)
- [ ] Error response: Internal errors don't leak details (check with invalid SQL in dev)
- [ ] Security headers present: `curl -I localhost:8080/api/health` shows headers
- [ ] Rate limiting: >100 req/min blocks with 429
- [ ] JWT: Expired tokens rejected, invalid signatures rejected

#### F3: Functional Verification
- [ ] Login works (JWT issued, cookie set)
- [ ] Create project, run scan, view findings (full flow)
- [ ] All existing features still work (apps, scans, findings, reports)
- [ ] Frontend validation shows errors for invalid inputs
- [ ] Backend validation returns 400 for invalid JSON

#### F4: Infrastructure Verification
- [ ] Docker Compose: `docker compose up` works, all services healthy
- [ ] Kubernetes: worker.yaml applies without socket mount
- [ ] Scanner binaries present in worker container: `docker exec <worker> which semgrep trivy gitleaks`
- [ ] Worker runs scan without docker.sock: `docker exec <worker> ls /var/run/` (no docker.sock)

---

## Success Criteria (Acceptance)

- [ ] **Zero docker socket mounts** in compose or kubernetes
- [ ] **Zero IDOR vulnerabilities** (all resource endpoints have ownership checks)
- [ ] **Input validation** on all POST/PATCH endpoints (backend + frontend)
- [ ] **Security headers** on all API responses
- [ ] **Error sanitization** in production mode
- [ ] **Rate limiting** works with user ID, fails closed
- [ ] **All existing tests pass** (if any exist)
- [ ] **Full scan flow works** (create project → run scan → view findings)

---

## Open Questions (Decisions Needed)

| # | Question | Impact | Recommendation |
|---|----------|--------|----------------|
| Q1 | **AppArmor**: Should we create a default profile or make it optional? | Medium | Create profile in repo, document how to enable |
| Q2 | **Scanner binaries**: Download at build time or provide script to install? | High | Download at build time for reproducibility |
| Q3 | **IDOR scope**: Middleware vs repository level ownership checks? | Medium | Middleware (cleaner, centralized) |
| Q4 | **Fail mode**: Should rate limiter fail-open or closed? | Medium | Fail-closed (security first) |
| Q5 | **Backward compat**: Should we support old Docker-based scanning? | Low | No, clean break in v1.4.0 |

---

## Auto-Resolved Items (No Questions Needed)

- **G1 Socket removal**: Confirmed via T9 (binaries) + T11 (image build)
- **G2 IDOR**: Confirmed via T8 (middleware) + T10 (apply to handlers)
- **G3 Validation**: Confirmed via T5 (setup) + T12 (apply)
- **G4 Errors**: Confirmed via T1 (sanitization)
- **G5 Headers**: Confirmed via T3 (middleware)
- **G6 JWT**: Confirmed via T2 (hardening)
- **G7 Rate Limit**: Confirmed via T4 (fixes)
- **G8/G9 Compose/K8s**: Confirmed via T6 (compose) + T7 (k8s)

---

## Dependency Graph

```
Wave 1 (Parallel):
  T1 ─┐
  T2 ─┤
  T3 ─┤
  T4 ─┤──> All can run simultaneously
  T5 ─┤
  T6 ─┤
  T7 ─┘

Wave 2 (Depends on Wave 1):
  T8 ── depends on T2 (JWT)
  T9 ── standalone (biggest task)

Wave 3 (Depends on Wave 2):
  T10 ─ depends on T8 (IDOR middleware)
  T11 ─ depends on T9 (binary execution)
  T12 ─ depends on T5 (validation setup)

Wave 4 (Depends on Wave 3):
  F1 ── Build verification
  F2 ── Security verification (depends on T1, T2, T3, T4)
  F3 ── Functional verification (depends on T10, T12)
  F4 ── Infrastructure verification (depends on T6, T7, T11)
```

---

## Next Steps

1. **Review this plan** — Check gaps, assumptions, open questions
2. **Answer open questions** (Q1-Q5) or accept my recommendations
3. **Approve plan** — I'll mark this plan as approved
4. **Run /start-work security-hardening-v1.4** — I'll create todos and start delegating tasks
5. **Monitor progress** — I'll spawn parallel agents for Wave 1 tasks immediately

---

**Plan Status**: DRAFT — Awaiting your review and approval.
