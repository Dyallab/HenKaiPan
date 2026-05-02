-- Demo workspace seed — creates sample data for evaluation
--
-- Usage:
--   docker compose exec -T postgres psql -U aspm -d aspm < scripts/seed-demo.sql
--
-- Run after migrations and before first use.

DO $$
DECLARE
    v_project_id UUID;
    v_scan_id    UUID;
    v_now        TIMESTAMPTZ := NOW();
BEGIN

-- ── Create demo project ─────────────────────────────────────────────────────

INSERT INTO projects (id, name, description, repo_url, provider, default_branch)
VALUES (gen_random_uuid(), 'Demo API Service', 'Sample Node.js REST API for evaluation', 'https://github.com/example/demo-api', 'github', 'main')
RETURNING id INTO v_project_id;

-- ── Create demo scans ───────────────────────────────────────────────────────

-- Scan 1: completed semgrep scan with findings
INSERT INTO scans (id, project_id, scanner, status, target, batch_id, created_at, started_at, completed_at, finding_count)
VALUES (gen_random_uuid(), v_project_id, 'semgrep', 'completed', 'https://github.com/example/demo-api', 'demo-batch', v_now - interval '3 days', v_now - interval '3 days' + interval '10 seconds', v_now - interval '3 days' + interval '2 minutes', 5)
RETURNING id INTO v_scan_id;

INSERT INTO findings (id, scan_id, project_id, scanner, rule_id, title, description, severity, file_path, line_start, line_end, code_snippet, created_at, status, fingerprint) VALUES
    (gen_random_uuid(), v_scan_id, v_project_id, 'semgrep', 'javascript.express.security.express-check-injection', 'SQL Injection in query builder', 'User input concatenated into SQL query', 'critical', 'src/db/users.js', 42, 45, 'db.query(`SELECT * FROM users WHERE id = ${req.params.id}`)', v_now - interval '3 days', 'open',
     encode(sha256('semgrep:javascript.express.security.express-check-injection:src/db/users.js:42'::bytea), 'hex')),
    (gen_random_uuid(), v_scan_id, v_project_id, 'semgrep', 'javascript.browser.security.dom-based-xss', 'DOM-based XSS in render function', 'Unescaped user input rendered to innerHTML', 'high', 'src/views/profile.js', 28, 30, 'element.innerHTML = userInput', v_now - interval '3 days', 'in_review',
     encode(sha256('semgrep:javascript.browser.security.dom-based-xss:src/views/profile.js:28'::bytea), 'hex')),
    (gen_random_uuid(), v_scan_id, v_project_id, 'semgrep', 'javascript.lang.security.audit.unsafe-var-parseint', 'Missing input validation on parseInt', 'parseInt used without radix parameter', 'medium', 'src/utils/parse.js', 15, 15, 'const id = parseInt(req.query.id)', v_now - interval '3 days', 'open',
     encode(sha256('semgrep:javascript.lang.security.audit.unsafe-var-parseint:src/utils/parse.js:15'::bytea), 'hex')),
    (gen_random_uuid(), v_scan_id, v_project_id, 'semgrep', 'javascript.express.security.express-jwt-hardcoded', 'Hardcoded JWT secret', 'JWT secret hardcoded in source code', 'high', 'src/auth/tokens.js', 3, 3, 'const secret = ''supersecret123''', v_now - interval '3 days', 'open',
     encode(sha256('semgrep:javascript.express.security.express-jwt-hardcoded:src/auth/tokens.js:3'::bytea), 'hex')),
    (gen_random_uuid(), v_scan_id, v_project_id, 'semgrep', 'javascript.lang.correctness.useless-eqeqeq', 'Useless equality check', 'Comparison using == instead of ===', 'info', 'src/validators/helpers.js', 67, 67, 'if (value == null)', v_now - interval '3 days', 'fixed',
     encode(sha256('semgrep:javascript.lang.correctness.useless-eqeqeq:src/validators/helpers.js:67'::bytea), 'hex'));

-- Scan 2: completed trivy scan
INSERT INTO scans (id, project_id, scanner, status, target, batch_id, created_at, started_at, completed_at, finding_count)
VALUES (gen_random_uuid(), v_project_id, 'trivy', 'completed', 'https://github.com/example/demo-api', 'demo-batch', v_now - interval '3 days', v_now - interval '3 days' + interval '5 seconds', v_now - interval '3 days' + interval '1 minute', 3)
RETURNING id INTO v_scan_id;

INSERT INTO findings (id, scan_id, project_id, scanner, rule_id, title, description, severity, file_path, line_start, line_end, code_snippet, created_at, status, fingerprint) VALUES
    (gen_random_uuid(), v_scan_id, v_project_id, 'trivy', 'CVE-2024-3094', 'XZ Utils backdoor (CVE-2024-3094)', 'Critical supply chain vulnerability in xz 5.6.0/5.6.1', 'critical', 'package-lock.json', 1, 1, 'xz@5.6.0', v_now - interval '3 days', 'open',
     encode(sha256('trivy:CVE-2024-3094:package-lock.json:1'::bytea), 'hex')),
    (gen_random_uuid(), v_scan_id, v_project_id, 'trivy', 'CVE-2024-21626', 'runC container escape (CVE-2024-21626)', 'High severity container escape in runC <=1.1.11', 'high', 'package-lock.json', 1, 1, 'runc@1.1.11', v_now - interval '3 days', 'open',
     encode(sha256('trivy:CVE-2024-21626:package-lock.json:1'::bytea), 'hex')),
    (gen_random_uuid(), v_scan_id, v_project_id, 'trivy', 'CVE-2023-44487', 'HTTP/2 rapid reset attack (CVE-2023-44487)', 'High severity DoS in HTTP/2 protocol handling', 'high', 'package-lock.json', 1, 1, 'node-fetch@2.6.9', v_now - interval '3 days', 'in_review',
     encode(sha256('trivy:CVE-2023-44487:package-lock.json:1'::bytea), 'hex'));

-- Scan 3: recent completed semgrep scan (re-scan, findings deduped)
INSERT INTO scans (id, project_id, scanner, status, target, batch_id, created_at, started_at, completed_at, finding_count)
VALUES (gen_random_uuid(), v_project_id, 'semgrep', 'completed', 'https://github.com/example/demo-api', 'demo-batch-2', v_now - interval '1 hour', v_now - interval '1 hour' + interval '8 seconds', v_now - interval '1 hour' + interval '90 seconds', 4)
RETURNING id INTO v_scan_id;

-- Re-insert findings — fingerprint dedup prevents actual duplicates
INSERT INTO findings (id, scan_id, project_id, scanner, rule_id, title, description, severity, file_path, line_start, line_end, code_snippet, created_at, status, fingerprint) VALUES
    (gen_random_uuid(), v_scan_id, v_project_id, 'semgrep', 'javascript.express.security.express-check-injection', 'SQL Injection in query builder', 'User input concatenated into SQL query', 'critical', 'src/db/users.js', 42, 45, 'db.query(`SELECT * FROM users WHERE id = ${req.params.id}`)', v_now - interval '1 hour', 'open',
     encode(sha256('semgrep:javascript.express.security.express-check-injection:src/db/users.js:42'::bytea), 'hex'))
ON CONFLICT (project_id, fingerprint) WHERE project_id IS NOT NULL AND fingerprint IS NOT NULL DO NOTHING;

-- Scan 4: running scan
INSERT INTO scans (id, project_id, scanner, status, target, batch_id, created_at, started_at)
VALUES (gen_random_uuid(), v_project_id, 'gitleaks', 'running', 'https://github.com/example/demo-api', 'demo-batch-2', v_now, v_now);

RAISE NOTICE 'Demo workspace seeded successfully. Project ID: %', v_project_id;

END $$;
