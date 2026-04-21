CREATE TABLE IF NOT EXISTS knowledge_articles (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    slug         TEXT NOT NULL UNIQUE,
    title        TEXT NOT NULL,
    content_md   TEXT NOT NULL,
    tags         TEXT[] NOT NULL DEFAULT '{}',
    cwe_ids      TEXT[] NOT NULL DEFAULT '{}',
    rule_ids     TEXT[] NOT NULL DEFAULT '{}',
    scanner      TEXT NOT NULL DEFAULT '',
    auto_generated BOOLEAN NOT NULL DEFAULT FALSE,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ka_tags    ON knowledge_articles USING gin(tags);
CREATE INDEX IF NOT EXISTS idx_ka_cwes    ON knowledge_articles USING gin(cwe_ids);
CREATE INDEX IF NOT EXISTS idx_ka_rules   ON knowledge_articles USING gin(rule_ids);
CREATE INDEX IF NOT EXISTS idx_ka_scanner ON knowledge_articles(scanner);

-- Seed: G304 – File Inclusion via Variable (gosec)
INSERT INTO knowledge_articles (slug, title, content_md, tags, cwe_ids, rule_ids, scanner) VALUES (
'gosec-g304-file-inclusion',
'G304 — File Inclusion via Variable (Gosec)',
$MD$
## What is this?

Gosec rule **G304** fires when a `os.Open`, `ioutil.ReadFile`, or similar call uses a variable as the file path without validation. An attacker who controls the input could read arbitrary files from the server (path traversal / LFI).

## Impact

- **Confidentiality:** read `/etc/passwd`, app secrets, private keys.
- **Severity:** High (can escalate to full compromise).

## How to fix

**Option 1 — Whitelist allowed paths:**

```go
// Before (vulnerable)
f, err := os.Open(userInput)

// After — clean path and restrict to a safe root
import "path/filepath"

safeRoot := "/app/uploads"
clean    := filepath.Clean(filepath.Join(safeRoot, userInput))
if !strings.HasPrefix(clean, safeRoot+"/") {
    return errors.New("invalid path")
}
f, err := os.Open(clean)
```

**Option 2 — Use an allow-list of filenames:**

```go
allowed := map[string]bool{"report.pdf": true, "invoice.csv": true}
if !allowed[filename] {
    return errors.New("file not allowed")
}
```

## References

- [CWE-22: Path Traversal](https://cwe.mitre.org/data/definitions/22.html)
- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [Gosec G304 docs](https://github.com/securego/gosec)
$MD$,
ARRAY['path-traversal','go','file-inclusion'],
ARRAY['CWE-22','CWE-73'],
ARRAY['G304'],
'gosec'
) ON CONFLICT (slug) DO NOTHING;

-- Seed: G301 – Directory permissions (gosec)
INSERT INTO knowledge_articles (slug, title, content_md, tags, cwe_ids, rule_ids, scanner) VALUES (
'gosec-g301-directory-permissions',
'G301 — Overly Permissive Directory (Gosec)',
$MD$
## What is this?

Gosec rule **G301** fires when `os.Mkdir` or `os.MkdirAll` is called with permissions wider than `0750`. World-writable or world-readable directories let other processes on the same host read or tamper with files.

## Impact

- **Integrity / Confidentiality:** other users on the system can read logs, temp files, or config dropped in that directory.
- **Severity:** Medium.

## How to fix

```go
// Before (vulnerable) — world-readable
os.MkdirAll("/var/myapp/data", 0755)

// After — group-readable only
os.MkdirAll("/var/myapp/data", 0750)

// Or owner-only
os.MkdirAll("/var/myapp/secrets", 0700)
```

Use `0700` for directories containing secrets, `0750` for directories read by a service group, never `0777`.

## References

- [CWE-732: Incorrect Permission Assignment](https://cwe.mitre.org/data/definitions/732.html)
- [Linux file permissions](https://man7.org/linux/man-pages/man1/chmod.1.html)
$MD$,
ARRAY['permissions','go','filesystem'],
ARRAY['CWE-732'],
ARRAY['G301'],
'gosec'
) ON CONFLICT (slug) DO NOTHING;

-- Seed: CKV2_GHA_1 – GitHub Actions pin by hash (checkov)
INSERT INTO knowledge_articles (slug, title, content_md, tags, cwe_ids, rule_ids, scanner) VALUES (
'checkov-ckv2-gha1-actions-pin',
'CKV2_GHA_1 — Pin GitHub Actions to a full commit SHA (Checkov)',
$MD$
## What is this?

Checkov rule **CKV2_GHA_1** fires when a GitHub Actions workflow uses a third-party action with a mutable ref (`@v3`, `@main`) instead of a pinned commit SHA. A supply-chain attacker who compromises the action repo can push malicious code to that tag.

## Impact

- **Supply-chain attack:** malicious code runs in your CI with access to secrets, tokens, and your codebase.
- **Severity:** Medium–High (depends on secrets available in CI).

## How to fix

```yaml
# Before (vulnerable)
- uses: actions/checkout@v4
- uses: some-org/some-action@main

# After — pinned to full SHA
- uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
- uses: some-org/some-action@a1b2c3d4e5f6... # v1.3.0
```

**Tooling:** use [pin-github-action](https://github.com/mheap/pin-github-action) or [Dependabot](https://docs.github.com/en/code-security/dependabot/working-with-dependabot/keeping-your-actions-up-to-date-with-dependabot) to automate SHA pinning.

## References

- [SLSA Supply-chain threats](https://slsa.dev/spec/v1.0/threats)
- [GitHub: Security hardening for GitHub Actions](https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions)
- [StepSecurity Harden-Runner](https://github.com/step-security/harden-runner)
$MD$,
ARRAY['ci-cd','supply-chain','github-actions','iac'],
ARRAY['CWE-829'],
ARRAY['CKV2_GHA_1'],
'checkov'
) ON CONFLICT (slug) DO NOTHING;

-- Seed: Wildcard CORS (semgrep)
INSERT INTO knowledge_articles (slug, title, content_md, tags, cwe_ids, rule_ids, scanner) VALUES (
'semgrep-wildcard-cors',
'Wildcard CORS — Access-Control-Allow-Origin: * (Semgrep)',
$MD$
## What is this?

A wildcard `Access-Control-Allow-Origin: *` header allows any website to make credentialed cross-origin requests to your API. Combined with `Access-Control-Allow-Credentials: true` it leaks authenticated responses to attacker-controlled pages.

## Impact

- **Data theft:** malicious site reads API responses on behalf of a logged-in user.
- **CSRF via CORS:** attacker can trigger state-changing requests.
- **Severity:** High if credentials are involved, Medium otherwise.

## How to fix

**FastAPI / Python:**

```python
# Before (vulnerable)
app.add_middleware(CORSMiddleware, allow_origins=["*"])

# After — explicit allowlist
ALLOWED_ORIGINS = [
    "https://app.example.com",
    "https://admin.example.com",
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)
```

**Validate dynamically:**

```python
import os
ALLOWED = set(os.environ["CORS_ORIGINS"].split(","))

@app.middleware("http")
async def cors_check(request: Request, call_next):
    origin = request.headers.get("origin", "")
    if origin and origin not in ALLOWED:
        return Response(status_code=403)
    ...
```

## References

- [CWE-942: Overly Permissive CORS](https://cwe.mitre.org/data/definitions/942.html)
- [OWASP CORS Cheatsheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
$MD$,
ARRAY['cors','web','api','python'],
ARRAY['CWE-942','CWE-346'],
ARRAY['python.fastapi.security.wildcard-cors.wildcard-cors','wildcard-cors'],
'semgrep'
) ON CONFLICT (slug) DO NOTHING;

-- Seed: Missing USER in Dockerfile (checkov/kics)
INSERT INTO knowledge_articles (slug, title, content_md, tags, cwe_ids, rule_ids, scanner) VALUES (
'docker-missing-user',
'Missing USER Instruction in Dockerfile',
$MD$
## What is this?

Running a container as root (the default when no `USER` instruction is set) means that if a process inside the container is compromised, the attacker has root inside the container — which can be leveraged to escape to the host via kernel exploits, volume mounts, or privileged operations.

## Impact

- **Container escape:** root inside container + privileged mount → root on host.
- **Severity:** High.

## How to fix

```dockerfile
# Before (vulnerable — runs as root)
FROM python:3.12-slim
COPY . /app
CMD ["python", "app.py"]

# After — dedicated non-root user
FROM python:3.12-slim
RUN addgroup --system app && adduser --system --ingroup app app
WORKDIR /app
COPY --chown=app:app . .
USER app
CMD ["python", "app.py"]
```

**For multi-stage builds:**

```dockerfile
FROM node:20-alpine AS build
WORKDIR /app
COPY . .
RUN npm ci && npm run build

FROM nginx:alpine
COPY --from=build /app/dist /usr/share/nginx/html
USER nginx   # nginx image ships a non-root user
```

## References

- [CWE-250: Execution with Unnecessary Privileges](https://cwe.mitre.org/data/definitions/250.html)
- [Docker security best practices](https://docs.docker.com/develop/security-best-practices/)
- [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker)
$MD$,
ARRAY['docker','containers','least-privilege','iac'],
ARRAY['CWE-250','CWE-269'],
ARRAY['CKV_DOCKER_3','dockerfile.security.missing-user.missing-user','Missing User Instruction'],
'checkov'
) ON CONFLICT (slug) DO NOTHING;
