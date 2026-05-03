-- Demo workspace seed — creates sample data for evaluation
-- Compatible with schema v031+
--
-- Usage:
--   docker compose exec -T postgres psql -U aspm -d aspm < scripts/seed-demo.sql
--
-- Run after migrations and before first use.
-- Idempotent: safe to re-run (uses ON CONFLICT DO NOTHING).

DO $$
DECLARE
    v_team_id    UUID;
    v_user_id    UUID;
    v_app_id     UUID;
    v_repo_id    UUID;
    v_project_id UUID;
    v_scan1_id   UUID;
    v_scan2_id   UUID;
    v_scan3_id   UUID;
    v_scan4_id   UUID;
    v_batch1     UUID;
    v_batch2     UUID;
    v_now        TIMESTAMPTZ := NOW();
BEGIN

-- ── Team ─────────────────────────────────────────────────────────────────────

INSERT INTO teams (id, name, created_at)
VALUES (gen_random_uuid(), 'Security Team', v_now)
ON CONFLICT (name) DO NOTHING;

SELECT id INTO v_team_id FROM teams WHERE name = 'Security Team';

-- ── User (reuse existing admin from migration 006 if present) ────────────────

SELECT id INTO v_user_id FROM users WHERE username = 'admin';

IF v_user_id IS NULL THEN
    INSERT INTO users (id, username, email, password_hash, role, created_at)
    VALUES (gen_random_uuid(), 'admin', 'admin@henkaipan.demo',
            '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgfeQ0VHgO5l9nD3fBGqO3Y0eFXa',
            'admin', v_now)
    RETURNING id INTO v_user_id;
END IF;

INSERT INTO team_members (team_id, user_id)
VALUES (v_team_id, v_user_id)
ON CONFLICT DO NOTHING;

-- ── App ──────────────────────────────────────────────────────────────────────

INSERT INTO apps (id, name, description, team_id, created_at, updated_at)
VALUES (gen_random_uuid(), 'Demo App', 'Demo application for evaluation', v_team_id, v_now, v_now)
ON CONFLICT (name) DO NOTHING;

SELECT id INTO v_app_id FROM apps WHERE name = 'Demo App';

-- ── Repo ─────────────────────────────────────────────────────────────────────

INSERT INTO repos (id, name, url, created_at, updated_at)
VALUES (gen_random_uuid(), 'demo-api', 'https://github.com/example/demo-api', v_now, v_now)
ON CONFLICT (url) DO NOTHING;

SELECT id INTO v_repo_id FROM repos WHERE url = 'https://github.com/example/demo-api';

-- ── Project ──────────────────────────────────────────────────────────────────

INSERT INTO projects (id, name, description, app_id, repo_id, repo_url, provider, default_branch, created_at, updated_at)
VALUES (gen_random_uuid(), 'Demo API Service', 'Sample Node.js REST API for evaluation',
        v_app_id, v_repo_id, 'https://github.com/example/demo-api', 'github', 'main', v_now, v_now)
ON CONFLICT DO NOTHING
RETURNING id INTO v_project_id;

IF v_project_id IS NULL THEN
    SELECT id INTO v_project_id FROM projects WHERE name = 'Demo API Service';
END IF;

-- ── Batches ─────────────────────────────────────────────────────────────────

v_batch1 := gen_random_uuid();
v_batch2 := gen_random_uuid();

-- ── Scan 1: completed semgrep scan ──────────────────────────────────────────

INSERT INTO scans (id, repo_id, project_id, scanner, status, target, scan_batch_id, created_at, started_at, completed_at)
VALUES (gen_random_uuid(), v_repo_id, v_project_id, 'semgrep', 'completed',
        'https://github.com/example/demo-api', v_batch1,
        v_now - interval '3 days', v_now - interval '3 days' + interval '10 seconds', v_now - interval '3 days' + interval '2 minutes')
RETURNING id INTO v_scan1_id;

INSERT INTO findings (id, scan_id, project_id, scanner, rule_id, title, description, severity, file_path, line_start, line_end, code_snippet, status, fingerprint, created_at, sla_deadline)
VALUES
    (gen_random_uuid(), v_scan1_id, v_project_id, 'semgrep',
     'javascript.express.security.express-check-injection', 'SQL Injection in query builder',
     'User input concatenated into SQL query', 'critical',
     'src/db/users.js', 42, 45, 'db.query(`SELECT * FROM users WHERE id = ${req.params.id}`)', 'open',
     encode(sha256('semgrep:javascript.express.security.express-check-injection:src/db/users.js:42'::bytea), 'hex'),
     v_now - interval '3 days', v_now - interval '3 days' + interval '24 hours'),
    (gen_random_uuid(), v_scan1_id, v_project_id, 'semgrep',
     'javascript.browser.security.dom-based-xss', 'DOM-based XSS in render function',
     'Unescaped user input rendered to innerHTML', 'high',
     'src/views/profile.js', 28, 30, 'element.innerHTML = userInput', 'in_review',
     encode(sha256('semgrep:javascript.browser.security.dom-based-xss:src/views/profile.js:28'::bytea), 'hex'),
     v_now - interval '3 days', v_now - interval '3 days' + interval '72 hours'),
    (gen_random_uuid(), v_scan1_id, v_project_id, 'semgrep',
     'javascript.lang.security.audit.unsafe-var-parseint', 'Missing input validation on parseInt',
     'parseInt used without radix parameter', 'medium',
     'src/utils/parse.js', 15, 15, 'const id = parseInt(req.query.id)', 'open',
     encode(sha256('semgrep:javascript.lang.security.audit.unsafe-var-parseint:src/utils/parse.js:15'::bytea), 'hex'),
     v_now - interval '3 days', v_now - interval '3 days' + interval '30 days'),
    (gen_random_uuid(), v_scan1_id, v_project_id, 'semgrep',
     'javascript.express.security.express-jwt-hardcoded', 'Hardcoded JWT secret',
     'JWT secret hardcoded in source code', 'high',
     'src/auth/tokens.js', 3, 3, 'const secret = ''supersecret123''', 'open',
     encode(sha256('semgrep:javascript.express.security.express-jwt-hardcoded:src/auth/tokens.js:3'::bytea), 'hex'),
     v_now - interval '3 days', v_now - interval '3 days' + interval '72 hours'),
    (gen_random_uuid(), v_scan1_id, v_project_id, 'semgrep',
     'javascript.lang.correctness.useless-eqeqeq', 'Useless equality check',
     'Comparison using == instead of ===', 'info',
     'src/validators/helpers.js', 67, 67, 'if (value == null)', 'fixed',
     encode(sha256('semgrep:javascript.lang.correctness.useless-eqeqeq:src/validators/helpers.js:67'::bytea), 'hex'),
     v_now - interval '3 days', NULL)
ON CONFLICT (project_id, fingerprint) WHERE project_id IS NOT NULL AND fingerprint IS NOT NULL DO NOTHING;

-- ── Scan 2: completed trivy scan ─────────────────────────────────────────────

INSERT INTO scans (id, repo_id, project_id, scanner, status, target, scan_batch_id, created_at, started_at, completed_at)
VALUES (gen_random_uuid(), v_repo_id, v_project_id, 'trivy', 'completed',
        'https://github.com/example/demo-api', v_batch1,
        v_now - interval '3 days', v_now - interval '3 days' + interval '5 seconds', v_now - interval '3 days' + interval '1 minute')
RETURNING id INTO v_scan2_id;

INSERT INTO findings (id, scan_id, project_id, scanner, rule_id, cve_id, title, description, severity, file_path, line_start, line_end, code_snippet, status, fingerprint, created_at, sla_deadline)
VALUES
    (gen_random_uuid(), v_scan2_id, v_project_id, 'trivy',
     'CVE-2024-3094', 'CVE-2024-3094', 'XZ Utils backdoor (CVE-2024-3094)',
     'Critical supply chain vulnerability in xz 5.6.0/5.6.1', 'critical',
     'package-lock.json', 1, 1, 'xz@5.6.0', 'open',
     encode(sha256('trivy:CVE-2024-3094:package-lock.json:1'::bytea), 'hex'),
     v_now - interval '3 days', v_now - interval '3 days' + interval '24 hours'),
    (gen_random_uuid(), v_scan2_id, v_project_id, 'trivy',
     'CVE-2024-21626', 'CVE-2024-21626', 'runC container escape (CVE-2024-21626)',
     'High severity container escape in runC <=1.1.11', 'high',
     'package-lock.json', 1, 1, 'runc@1.1.11', 'open',
     encode(sha256('trivy:CVE-2024-21626:package-lock.json:1'::bytea), 'hex'),
     v_now - interval '3 days', v_now - interval '3 days' + interval '72 hours'),
    (gen_random_uuid(), v_scan2_id, v_project_id, 'trivy',
     'CVE-2023-44487', 'CVE-2023-44487', 'HTTP/2 rapid reset attack (CVE-2023-44487)',
     'High severity DoS in HTTP/2 protocol handling', 'high',
     'package-lock.json', 1, 1, 'node-fetch@2.6.9', 'in_review',
     encode(sha256('trivy:CVE-2023-44487:package-lock.json:1'::bytea), 'hex'),
     v_now - interval '3 days', v_now - interval '3 days' + interval '72 hours')
ON CONFLICT (project_id, fingerprint) WHERE project_id IS NOT NULL AND fingerprint IS NOT NULL DO NOTHING;

-- ── Scan 3: re-scan (dedup test) ────────────────────────────────────────────

INSERT INTO scans (id, repo_id, project_id, scanner, status, target, scan_batch_id, created_at, started_at, completed_at)
VALUES (gen_random_uuid(), v_repo_id, v_project_id, 'semgrep', 'completed',
        'https://github.com/example/demo-api', v_batch2,
        v_now - interval '1 hour', v_now - interval '1 hour' + interval '8 seconds', v_now - interval '1 hour' + interval '90 seconds')
RETURNING id INTO v_scan3_id;

INSERT INTO findings (id, scan_id, project_id, scanner, rule_id, title, description, severity, file_path, line_start, line_end, code_snippet, status, fingerprint, created_at, sla_deadline)
VALUES
    (gen_random_uuid(), v_scan3_id, v_project_id, 'semgrep',
     'javascript.express.security.express-check-injection', 'SQL Injection in query builder',
     'User input concatenated into SQL query', 'critical',
     'src/db/users.js', 42, 45, 'db.query(`SELECT * FROM users WHERE id = ${req.params.id}`)', 'open',
     encode(sha256('semgrep:javascript.express.security.express-check-injection:src/db/users.js:42'::bytea), 'hex'),
     v_now - interval '1 hour', v_now - interval '1 hour' + interval '24 hours')
ON CONFLICT (project_id, fingerprint) WHERE project_id IS NOT NULL AND fingerprint IS NOT NULL DO NOTHING;

-- ── Scan 4: running (in-progress) ────────────────────────────────────────────

INSERT INTO scans (id, repo_id, project_id, scanner, status, target, scan_batch_id, created_at, started_at)
VALUES (gen_random_uuid(), v_repo_id, v_project_id, 'gitleaks', 'running',
        'https://github.com/example/demo-api', v_batch2,
        v_now, v_now);

RAISE NOTICE 'Demo workspace seeded. Project ID: %', v_project_id;

END $$;