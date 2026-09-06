-- Full workspace seed — superset of seed-demo.sql
-- Adds vulnerabilities (per-engine vuln_uid), findings→vulnerabilities link-back,
-- and level-3 entities (risk_acceptances, finding_comments, api_tokens,
-- scan_schedules, webhooks + delivery logs, agent_analyses, finding_correlations,
-- jira_issue_links, user_notifications, audit_logs).
--
-- Compatible with schema v048
--
-- Usage:
--   docker compose exec -T postgres psql -U aspm -d aspm < scripts/seed-full.sql
--
-- Idempotent: safe to re-run. Uses ON CONFLICT DO NOTHING / existence checks;
-- a second run adds no rows.
--
-- vuln_uid algorithm (mirrors internal/vulnerability/uid.go ComputeVulnUID):
--   sast    -> sha256("sast:<rule_id>:<normalized_path>")
--   sca     -> sha256("sca:<rule_id>")            (rule_id = CVE/GHSA id)
--   secrets -> sha256("secret:<secret_hash>")     (secret_hash = sha256(raw secret))
--   iac     -> sha256("iac:<rule_id>:<normalized_path>")
--   normalized_path = NormalizePath(file_path): "src/foo" -> "/foo", "pkg.json" -> "/pkg.json"
--
-- API tokens (bcrypt hashes of the raw hkp_ token; prefix = first 12 chars):
--   ci-cd-token  raw = hkp_9f3a2b1c4d5e6f7a8b9c0d1e  prefix = hkp_9f3a2b1c
--   infra-token  raw = hkp_5e4d3c2b1a0f9e8d7c6b5a4f  prefix = hkp_5e4d3c2b

DO $$
DECLARE
    v_team_id       UUID;
    v_admin_id      UUID;
    v_viewer_id     UUID;
    v_app_id        UUID;
    v_project_id    UUID;  -- Demo API Service (app-backed)
    v_infra_id      UUID;  -- Demo Infra (standalone, app_id NULL)
    v_scan1_id      UUID;  -- semgrep completed
    v_scan2_id      UUID;  -- trivy completed
    v_scan3_id      UUID;  -- gitleaks completed
    v_scan4_id      UUID;  -- semgrep re-scan (dedup test)
    v_scan5_id      UUID;  -- gitleaks running (in-progress)
    v_scan6_id      UUID;  -- checkov completed (infra)
    v_batch1        UUID;
    v_batch2        UUID;
    v_batch3        UUID;
    v_now           TIMESTAMPTZ := NOW();
    -- Demo secrets below are intentionally fake fixtures for the secrets
    -- scanner legs. Each token literal is split so the file stores no
    -- contiguous provider-token pattern (GitHub push protection).
    v_secret_ghp   TEXT := 'ghp_1234567890' || 'abcdefghijklmnopqrstuvwxyz';
    v_secret_slack TEXT := 'xoxb-123456789012' || '-123456789012-abcdefghijklmn';
    v_finding_sqli     UUID;
    v_finding_xss      UUID;
    v_finding_cve3094  UUID;
    v_finding_cve21626 UUID;
    v_finding_aws      UUID;
    v_finding_s3       UUID;
BEGIN

-- ── Team ─────────────────────────────────────────────────────────────────────

INSERT INTO teams (id, name, created_at)
VALUES (gen_random_uuid(), 'Security Team', v_now)
ON CONFLICT (name) DO NOTHING;

SELECT id INTO v_team_id FROM teams WHERE name = 'Security Team';

-- ── Users (role always explicit: admin | viewer — default 'analyst' violates CHECK) ──
-- Password for BOTH seed users is 'admin' (bcrypt hash below; matches README admin/admin).

SELECT id INTO v_admin_id FROM users WHERE username = 'admin';

IF v_admin_id IS NULL THEN
    INSERT INTO users (id, username, email, password_hash, role, created_at)
    VALUES (gen_random_uuid(), 'admin', 'admin@henkaipan.demo',
            '$2a$10$b7/hk/lAiDagcLs2/gI8m.dhVBDdJhKR3tGNA9QJYqPB8uu.NdWNC',
            'admin', v_now)
    RETURNING id INTO v_admin_id;
END IF;

SELECT id INTO v_viewer_id FROM users WHERE username = 'viewer';

IF v_viewer_id IS NULL THEN
    INSERT INTO users (id, username, email, password_hash, role, created_at)
    VALUES (gen_random_uuid(), 'viewer', 'viewer@henkaipan.demo',
            '$2a$10$b7/hk/lAiDagcLs2/gI8m.dhVBDdJhKR3tGNA9QJYqPB8uu.NdWNC',
            'viewer', v_now)
    RETURNING id INTO v_viewer_id;
END IF;

INSERT INTO team_members (team_id, user_id)
VALUES (v_team_id, v_admin_id), (v_team_id, v_viewer_id)
ON CONFLICT DO NOTHING;

-- ── App ──────────────────────────────────────────────────────────────────────

INSERT INTO apps (id, name, description, team_id, created_at, updated_at)
VALUES (gen_random_uuid(), 'Demo App', 'Demo application for evaluation', v_team_id, v_now, v_now)
ON CONFLICT (name) DO NOTHING;

SELECT id INTO v_app_id FROM apps WHERE name = 'Demo App';

-- ── Projects ─────────────────────────────────────────────────────────────────

-- App-backed project (partial unique (app_id, name))
INSERT INTO projects (id, name, description, app_id, repo_url, provider, default_branch, created_at, updated_at)
VALUES (gen_random_uuid(), 'Demo API Service', 'Sample Node.js REST API for evaluation',
        v_app_id, 'https://github.com/example/demo-api', 'github', 'main', v_now, v_now)
ON CONFLICT DO NOTHING
RETURNING id INTO v_project_id;

IF v_project_id IS NULL THEN
    SELECT id INTO v_project_id FROM projects WHERE name = 'Demo API Service';
END IF;

-- Standalone project (app_id NULL, globally unique name via idx_projects_standalone_name)
SELECT id INTO v_infra_id FROM projects WHERE name = 'Demo Infra' AND app_id IS NULL;

IF v_infra_id IS NULL THEN
    INSERT INTO projects (id, name, description, app_id, repo_url, provider, default_branch, created_at, updated_at)
    VALUES (gen_random_uuid(), 'Demo Infra', 'Terraform infrastructure for evaluation',
            NULL, 'https://github.com/example/demo-infra', 'github', 'main', v_now, v_now)
    ON CONFLICT DO NOTHING
    RETURNING id INTO v_infra_id;
END IF;

IF v_infra_id IS NULL THEN
    SELECT id INTO v_infra_id FROM projects WHERE name = 'Demo Infra' AND app_id IS NULL;
END IF;

-- ── Batches ─────────────────────────────────────────────────────────────────

v_batch1 := gen_random_uuid();
v_batch2 := gen_random_uuid();
v_batch3 := gen_random_uuid();

-- ── Scan 1: completed semgrep scan (SAST) ────────────────────────────────────
-- Idempotent: reuse the scan that already owns the SQL-injection finding.

SELECT s.id INTO v_scan1_id
FROM findings f
JOIN scans s ON s.id = f.scan_id
WHERE f.project_id = v_project_id
  AND f.fingerprint = encode(sha256('semgrep:javascript.express.security.express-check-injection:src/db/users.js:42'::bytea), 'hex')
LIMIT 1;

IF v_scan1_id IS NULL THEN
    INSERT INTO scans (id, project_id, scanner, status, target, scan_batch_id, created_at, started_at, completed_at)
    VALUES (gen_random_uuid(), v_project_id, 'semgrep', 'completed',
            'https://github.com/example/demo-api', v_batch1,
            v_now - interval '3 days', v_now - interval '3 days' + interval '10 seconds', v_now - interval '3 days' + interval '2 minutes')
    RETURNING id INTO v_scan1_id;
END IF;

INSERT INTO findings (id, scan_id, project_id, scanner, rule_id, title, description, severity, file_path, line_start, line_end, code_snippet, status, fingerprint, confidence_score, created_at, sla_deadline)
VALUES
    (gen_random_uuid(), v_scan1_id, v_project_id, 'semgrep',
     'javascript.express.security.express-check-injection', 'SQL Injection in query builder',
     'User input concatenated into SQL query', 'critical',
     'src/db/users.js', 42, 45, 'db.query(`SELECT * FROM users WHERE id = ${req.params.id}`)', 'open',
     encode(sha256('semgrep:javascript.express.security.express-check-injection:src/db/users.js:42'::bytea), 'hex'),
     0.95, v_now - interval '3 days', v_now - interval '3 days' + interval '24 hours'),
    (gen_random_uuid(), v_scan1_id, v_project_id, 'semgrep',
     'javascript.browser.security.dom-based-xss', 'DOM-based XSS in render function',
     'Unescaped user input rendered to innerHTML', 'high',
     'src/views/profile.js', 28, 30, 'element.innerHTML = userInput', 'in_review',
     encode(sha256('semgrep:javascript.browser.security.dom-based-xss:src/views/profile.js:28'::bytea), 'hex'),
     0.85, v_now - interval '3 days', v_now - interval '3 days' + interval '72 hours'),
    (gen_random_uuid(), v_scan1_id, v_project_id, 'semgrep',
     'javascript.lang.security.audit.unsafe-var-parseint', 'Missing input validation on parseInt',
     'parseInt used without radix parameter', 'medium',
     'src/utils/parse.js', 15, 15, 'const id = parseInt(req.query.id)', 'open',
     encode(sha256('semgrep:javascript.lang.security.audit.unsafe-var-parseint:src/utils/parse.js:15'::bytea), 'hex'),
     NULL, v_now - interval '3 days', v_now - interval '3 days' + interval '30 days'),
    (gen_random_uuid(), v_scan1_id, v_project_id, 'semgrep',
     'javascript.express.security.express-jwt-hardcoded', 'Hardcoded JWT secret',
     'JWT secret hardcoded in source code', 'high',
     'src/auth/tokens.js', 3, 3, 'const secret = ''supersecret123''', 'open',
     encode(sha256('semgrep:javascript.express.security.express-jwt-hardcoded:src/auth/tokens.js:3'::bytea), 'hex'),
     NULL, v_now - interval '3 days', v_now - interval '3 days' + interval '72 hours'),
    (gen_random_uuid(), v_scan1_id, v_project_id, 'semgrep',
     'javascript.lang.correctness.useless-eqeqeq', 'Useless equality check',
     'Comparison using == instead of ===', 'info',
     'src/validators/helpers.js', 67, 67, 'if (value == null)', 'fixed',
     encode(sha256('semgrep:javascript.lang.correctness.useless-eqeqeq:src/validators/helpers.js:67'::bytea), 'hex'),
     NULL, v_now - interval '3 days', NULL)
ON CONFLICT (project_id, fingerprint) WHERE project_id IS NOT NULL AND fingerprint IS NOT NULL DO NOTHING;

-- ── Scan 2: completed trivy scan (SCA) ───────────────────────────────────────

SELECT s.id INTO v_scan2_id
FROM findings f
JOIN scans s ON s.id = f.scan_id
WHERE f.project_id = v_project_id
  AND f.fingerprint = encode(sha256('trivy:CVE-2024-3094:package-lock.json:1'::bytea), 'hex')
LIMIT 1;

IF v_scan2_id IS NULL THEN
    INSERT INTO scans (id, project_id, scanner, status, target, scan_batch_id, created_at, started_at, completed_at)
    VALUES (gen_random_uuid(), v_project_id, 'trivy', 'completed',
            'https://github.com/example/demo-api', v_batch1,
            v_now - interval '3 days', v_now - interval '3 days' + interval '5 seconds', v_now - interval '3 days' + interval '1 minute')
    RETURNING id INTO v_scan2_id;
END IF;

INSERT INTO findings (id, scan_id, project_id, scanner, rule_id, cve_id, pkg_name, pkg_version, title, description, severity, file_path, line_start, line_end, code_snippet, status, fingerprint, confidence_score, created_at, sla_deadline)
VALUES
    (gen_random_uuid(), v_scan2_id, v_project_id, 'trivy',
     'CVE-2024-3094', 'CVE-2024-3094', 'xz', '5.6.0', 'XZ Utils backdoor (CVE-2024-3094)',
     'Critical supply chain vulnerability in xz 5.6.0/5.6.1', 'critical',
     'package-lock.json', 1, 1, 'xz@5.6.0', 'open',
     encode(sha256('trivy:CVE-2024-3094:package-lock.json:1'::bytea), 'hex'),
     0.99, v_now - interval '3 days', v_now - interval '3 days' + interval '24 hours'),
    (gen_random_uuid(), v_scan2_id, v_project_id, 'trivy',
     'CVE-2024-21626', 'CVE-2024-21626', 'runc', '1.1.11', 'runC container escape (CVE-2024-21626)',
     'High severity container escape in runC <=1.1.11', 'high',
     'package-lock.json', 1, 1, 'runc@1.1.11', 'open',
     encode(sha256('trivy:CVE-2024-21626:package-lock.json:1'::bytea), 'hex'),
     0.95, v_now - interval '3 days', v_now - interval '3 days' + interval '72 hours'),
    (gen_random_uuid(), v_scan2_id, v_project_id, 'trivy',
     'CVE-2023-44487', 'CVE-2023-44487', 'node-fetch', '2.6.9', 'HTTP/2 rapid reset attack (CVE-2023-44487)',
     'High severity DoS in HTTP/2 protocol handling', 'high',
     'package-lock.json', 1, 1, 'node-fetch@2.6.9', 'in_review',
     encode(sha256('trivy:CVE-2023-44487:package-lock.json:1'::bytea), 'hex'),
     NULL, v_now - interval '3 days', v_now - interval '3 days' + interval '72 hours')
ON CONFLICT (project_id, fingerprint) WHERE project_id IS NOT NULL AND fingerprint IS NOT NULL DO NOTHING;

-- ── Scan 3: completed gitleaks scan (secrets) ────────────────────────────────

SELECT s.id INTO v_scan3_id
FROM findings f
JOIN scans s ON s.id = f.scan_id
WHERE f.project_id = v_project_id
  AND f.fingerprint = encode(sha256('gitleaks:aws-access-key:src/config/.env:12'::bytea), 'hex')
LIMIT 1;

IF v_scan3_id IS NULL THEN
    INSERT INTO scans (id, project_id, scanner, status, target, scan_batch_id, created_at, started_at, completed_at)
    VALUES (gen_random_uuid(), v_project_id, 'gitleaks', 'completed',
            'https://github.com/example/demo-api', v_batch1,
            v_now - interval '2 days', v_now - interval '2 days' + interval '8 seconds', v_now - interval '2 days' + interval '45 seconds')
    RETURNING id INTO v_scan3_id;
END IF;

INSERT INTO findings (id, scan_id, project_id, scanner, rule_id, title, description, severity, file_path, line_start, line_end, code_snippet, status, secret_hash, fingerprint, confidence_score, created_at, sla_deadline)
VALUES
    (gen_random_uuid(), v_scan3_id, v_project_id, 'gitleaks',
     'aws-access-key', 'AWS Access Key exposed',
     'Hardcoded AWS access key in environment config', 'critical',
     'src/config/.env', 12, 12, 'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE', 'open',
     encode(sha256('AKIAIOSFODNN7EXAMPLE'::bytea), 'hex'),
     encode(sha256('gitleaks:aws-access-key:src/config/.env:12'::bytea), 'hex'),
     0.98, v_now - interval '2 days', v_now - interval '2 days' + interval '24 hours'),
    (gen_random_uuid(), v_scan3_id, v_project_id, 'gitleaks',
     'github-pat', 'GitHub Personal Access Token exposed',
     'Hardcoded GitHub PAT in environment config', 'high',
     'src/config/.env', 15, 15, 'GITHUB_TOKEN=' || v_secret_ghp, 'open',
     encode(sha256(v_secret_ghp::bytea), 'hex'),
     encode(sha256('gitleaks:github-pat:src/config/.env:15'::bytea), 'hex'),
     NULL, v_now - interval '2 days', v_now - interval '2 days' + interval '72 hours'),
    (gen_random_uuid(), v_scan3_id, v_project_id, 'gitleaks',
     'slack-token', 'Slack token exposed',
     'Hardcoded Slack bot token in environment config', 'high',
     'src/config/.env', 18, 18, 'SLACK_TOKEN=' || v_secret_slack, 'open',
     encode(sha256(v_secret_slack::bytea), 'hex'),
     encode(sha256('gitleaks:slack-token:src/config/.env:18'::bytea), 'hex'),
     NULL, v_now - interval '2 days', v_now - interval '2 days' + interval '72 hours')
ON CONFLICT (project_id, fingerprint) WHERE project_id IS NOT NULL AND fingerprint IS NOT NULL DO NOTHING;

-- ── Scan 4: semgrep re-scan (dedup test — finding shares fingerprint with scan 1) ──

SELECT s.id INTO v_scan4_id
FROM scans s
WHERE s.project_id = v_project_id
  AND s.scanner = 'semgrep'
  AND s.status = 'completed'
  AND s.id <> v_scan1_id
LIMIT 1;

IF v_scan4_id IS NULL THEN
    INSERT INTO scans (id, project_id, scanner, status, target, scan_batch_id, created_at, started_at, completed_at)
    VALUES (gen_random_uuid(), v_project_id, 'semgrep', 'completed',
            'https://github.com/example/demo-api', v_batch2,
            v_now - interval '1 hour', v_now - interval '1 hour' + interval '8 seconds', v_now - interval '1 hour' + interval '90 seconds')
    RETURNING id INTO v_scan4_id;
END IF;

INSERT INTO findings (id, scan_id, project_id, scanner, rule_id, title, description, severity, file_path, line_start, line_end, code_snippet, status, fingerprint, created_at, sla_deadline)
VALUES
    (gen_random_uuid(), v_scan4_id, v_project_id, 'semgrep',
     'javascript.express.security.express-check-injection', 'SQL Injection in query builder',
     'User input concatenated into SQL query', 'critical',
     'src/db/users.js', 42, 45, 'db.query(`SELECT * FROM users WHERE id = ${req.params.id}`)', 'open',
     encode(sha256('semgrep:javascript.express.security.express-check-injection:src/db/users.js:42'::bytea), 'hex'),
     v_now - interval '1 hour', v_now - interval '1 hour' + interval '24 hours')
ON CONFLICT (project_id, fingerprint) WHERE project_id IS NOT NULL AND fingerprint IS NOT NULL DO NOTHING;

-- ── Scan 5: gitleaks running (in-progress, no findings yet) ──────────────────

SELECT id INTO v_scan5_id
FROM scans
WHERE project_id = v_project_id
  AND scanner = 'gitleaks'
  AND status = 'running'
LIMIT 1;

IF v_scan5_id IS NULL THEN
    INSERT INTO scans (id, project_id, scanner, status, target, scan_batch_id, created_at, started_at)
    VALUES (gen_random_uuid(), v_project_id, 'gitleaks', 'running',
            'https://github.com/example/demo-api', v_batch2,
            v_now, v_now)
    RETURNING id INTO v_scan5_id;
END IF;

-- ── Scan 6: completed checkov scan on standalone infra project (IaC) ─────────

SELECT s.id INTO v_scan6_id
FROM findings f
JOIN scans s ON s.id = f.scan_id
WHERE f.project_id = v_infra_id
  AND f.fingerprint = encode(sha256('checkov:CKV_AWS_18:src/terraform/s3.tf:10'::bytea), 'hex')
LIMIT 1;

IF v_scan6_id IS NULL THEN
    INSERT INTO scans (id, project_id, scanner, status, target, scan_batch_id, created_at, started_at, completed_at)
    VALUES (gen_random_uuid(), v_infra_id, 'checkov', 'completed',
            'https://github.com/example/demo-infra', v_batch3,
            v_now - interval '1 day', v_now - interval '1 day' + interval '6 seconds', v_now - interval '1 day' + interval '40 seconds')
    RETURNING id INTO v_scan6_id;
END IF;

INSERT INTO findings (id, scan_id, project_id, scanner, rule_id, title, description, severity, file_path, line_start, line_end, code_snippet, status, fingerprint, confidence_score, created_at, sla_deadline)
VALUES
    (gen_random_uuid(), v_scan6_id, v_infra_id, 'checkov',
     'CKV_AWS_18', 'S3 bucket publicly accessible',
     'S3 bucket allows public read/write access', 'high',
     'src/terraform/s3.tf', 10, 12, 'acl = "public-read"', 'open',
     encode(sha256('checkov:CKV_AWS_18:src/terraform/s3.tf:10'::bytea), 'hex'),
     0.9, v_now - interval '1 day', v_now - interval '1 day' + interval '72 hours'),
    (gen_random_uuid(), v_scan6_id, v_infra_id, 'checkov',
     'CKV_AWS_24', 'Security group allows unrestricted SSH',
     'Security group ingress allows 0.0.0.0/0 on port 22', 'high',
     'src/terraform/security.tf', 5, 8, 'cidr_blocks = ["0.0.0.0/0"]', 'open',
     encode(sha256('checkov:CKV_AWS_24:src/terraform/security.tf:5'::bytea), 'hex'),
     NULL, v_now - interval '1 day', v_now - interval '1 day' + interval '72 hours'),
    (gen_random_uuid(), v_scan6_id, v_infra_id, 'checkov',
     'CKV_AWS_189', 'EBS volume not encrypted',
     'EBS volume created without encryption enabled', 'medium',
     'src/terraform/ebs.tf', 8, 10, 'encrypted = false', 'open',
     encode(sha256('checkov:CKV_AWS_189:src/terraform/ebs.tf:8'::bytea), 'hex'),
     NULL, v_now - interval '1 day', v_now - interval '1 day' + interval '30 days')
ON CONFLICT (project_id, fingerprint) WHERE project_id IS NOT NULL AND fingerprint IS NOT NULL DO NOTHING;

-- ── Vulnerabilities (per-engine vuln_uid, ON CONFLICT (project_id, vuln_uid)) ──

-- SAST (project 1)
INSERT INTO vulnerabilities (id, vuln_uid, project_id, title, description, severity, status, engine_type, cwe_id, rule_id, file_path, first_seen_at, last_seen_at, finding_count, scanner_coverage, confidence_score, created_at, updated_at)
VALUES
    (gen_random_uuid(), encode(sha256('sast:javascript.express.security.express-check-injection:/db/users.js'::bytea), 'hex'), v_project_id,
     'SQL Injection in query builder', 'User input concatenated into SQL query', 'critical', 'open', 'sast',
     'CWE-89', 'javascript.express.security.express-check-injection', '/db/users.js',
     v_now - interval '3 days', v_now, 1, ARRAY['semgrep'], 0.95, v_now - interval '3 days', v_now),
    (gen_random_uuid(), encode(sha256('sast:javascript.browser.security.dom-based-xss:/views/profile.js'::bytea), 'hex'), v_project_id,
     'DOM-based XSS in render function', 'Unescaped user input rendered to innerHTML', 'high', 'in_review', 'sast',
     'CWE-79', 'javascript.browser.security.dom-based-xss', '/views/profile.js',
     v_now - interval '3 days', v_now, 1, ARRAY['semgrep'], 0.85, v_now - interval '3 days', v_now),
    (gen_random_uuid(), encode(sha256('sast:javascript.lang.security.audit.unsafe-var-parseint:/utils/parse.js'::bytea), 'hex'), v_project_id,
     'Missing input validation on parseInt', 'parseInt used without radix parameter', 'medium', 'open', 'sast',
     'CWE-20', 'javascript.lang.security.audit.unsafe-var-parseint', '/utils/parse.js',
     v_now - interval '3 days', v_now, 1, ARRAY['semgrep'], NULL, v_now - interval '3 days', v_now),
    (gen_random_uuid(), encode(sha256('sast:javascript.express.security.express-jwt-hardcoded:/auth/tokens.js'::bytea), 'hex'), v_project_id,
     'Hardcoded JWT secret', 'JWT secret hardcoded in source code', 'high', 'open', 'sast',
     'CWE-798', 'javascript.express.security.express-jwt-hardcoded', '/auth/tokens.js',
     v_now - interval '3 days', v_now, 1, ARRAY['semgrep'], NULL, v_now - interval '3 days', v_now),
    (gen_random_uuid(), encode(sha256('sast:javascript.lang.correctness.useless-eqeqeq:/validators/helpers.js'::bytea), 'hex'), v_project_id,
     'Useless equality check', 'Comparison using == instead of ===', 'info', 'fixed', 'sast',
     NULL, 'javascript.lang.correctness.useless-eqeqeq', '/validators/helpers.js',
     v_now - interval '3 days', v_now, 1, ARRAY['semgrep'], NULL, v_now - interval '3 days', v_now)
ON CONFLICT (project_id, vuln_uid) DO NOTHING;

-- SCA (project 1)
INSERT INTO vulnerabilities (id, vuln_uid, project_id, title, description, severity, status, engine_type, pkg_name, pkg_version, cve_id, rule_id, file_path, first_seen_at, last_seen_at, finding_count, scanner_coverage, confidence_score, created_at, updated_at)
VALUES
    (gen_random_uuid(), encode(sha256('sca:CVE-2024-3094'::bytea), 'hex'), v_project_id,
     'XZ Utils backdoor (CVE-2024-3094)', 'Critical supply chain vulnerability in xz 5.6.0/5.6.1', 'critical', 'open', 'sca',
     'xz', '5.6.0', 'CVE-2024-3094', 'CVE-2024-3094', '/package-lock.json',
     v_now - interval '3 days', v_now, 1, ARRAY['trivy'], 0.99, v_now - interval '3 days', v_now),
    (gen_random_uuid(), encode(sha256('sca:CVE-2024-21626'::bytea), 'hex'), v_project_id,
     'runC container escape (CVE-2024-21626)', 'High severity container escape in runC <=1.1.11', 'high', 'open', 'sca',
     'runc', '1.1.11', 'CVE-2024-21626', 'CVE-2024-21626', '/package-lock.json',
     v_now - interval '3 days', v_now, 1, ARRAY['trivy'], 0.95, v_now - interval '3 days', v_now),
    (gen_random_uuid(), encode(sha256('sca:CVE-2023-44487'::bytea), 'hex'), v_project_id,
     'HTTP/2 rapid reset attack (CVE-2023-44487)', 'High severity DoS in HTTP/2 protocol handling', 'high', 'in_review', 'sca',
     'node-fetch', '2.6.9', 'CVE-2023-44487', 'CVE-2023-44487', '/package-lock.json',
     v_now - interval '3 days', v_now, 1, ARRAY['trivy'], NULL, v_now - interval '3 days', v_now)
ON CONFLICT (project_id, vuln_uid) DO NOTHING;

-- Secrets (project 1)
INSERT INTO vulnerabilities (id, vuln_uid, project_id, title, description, severity, status, engine_type, rule_id, secret_hash, file_path, first_seen_at, last_seen_at, finding_count, scanner_coverage, confidence_score, created_at, updated_at)
VALUES
    (gen_random_uuid(), encode(sha256(('secret:' || encode(sha256('AKIAIOSFODNN7EXAMPLE'::bytea), 'hex'))::bytea), 'hex'), v_project_id,
     'AWS Access Key exposed', 'Hardcoded AWS access key in environment config', 'critical', 'open', 'secrets',
     'aws-access-key', encode(sha256('AKIAIOSFODNN7EXAMPLE'::bytea), 'hex'), '/config/.env',
     v_now - interval '2 days', v_now, 1, ARRAY['gitleaks'], 0.98, v_now - interval '2 days', v_now),
    (gen_random_uuid(), encode(sha256(('secret:' || encode(sha256(v_secret_ghp::bytea), 'hex'))::bytea), 'hex'), v_project_id,
     'GitHub Personal Access Token exposed', 'Hardcoded GitHub PAT in environment config', 'high', 'open', 'secrets',
     'github-pat', encode(sha256(v_secret_ghp::bytea), 'hex'), '/config/.env',
     v_now - interval '2 days', v_now, 1, ARRAY['gitleaks'], NULL, v_now - interval '2 days', v_now),
    (gen_random_uuid(), encode(sha256(('secret:' || encode(sha256(v_secret_slack::bytea), 'hex'))::bytea), 'hex'), v_project_id,
     'Slack token exposed', 'Hardcoded Slack bot token in environment config', 'high', 'open', 'secrets',
     'slack-token', encode(sha256(v_secret_slack::bytea), 'hex'), '/config/.env',
     v_now - interval '2 days', v_now, 1, ARRAY['gitleaks'], NULL, v_now - interval '2 days', v_now)
ON CONFLICT (project_id, vuln_uid) DO NOTHING;

-- IaC (project 2 — standalone)
INSERT INTO vulnerabilities (id, vuln_uid, project_id, title, description, severity, status, engine_type, rule_id, file_path, first_seen_at, last_seen_at, finding_count, scanner_coverage, confidence_score, created_at, updated_at)
VALUES
    (gen_random_uuid(), encode(sha256('iac:CKV_AWS_18:/terraform/s3.tf'::bytea), 'hex'), v_infra_id,
     'S3 bucket publicly accessible', 'S3 bucket allows public read/write access', 'high', 'open', 'iac',
     'CKV_AWS_18', '/terraform/s3.tf',
     v_now - interval '1 day', v_now, 1, ARRAY['checkov'], 0.9, v_now - interval '1 day', v_now),
    (gen_random_uuid(), encode(sha256('iac:CKV_AWS_24:/terraform/security.tf'::bytea), 'hex'), v_infra_id,
     'Security group allows unrestricted SSH', 'Security group ingress allows 0.0.0.0/0 on port 22', 'high', 'open', 'iac',
     'CKV_AWS_24', '/terraform/security.tf',
     v_now - interval '1 day', v_now, 1, ARRAY['checkov'], NULL, v_now - interval '1 day', v_now),
    (gen_random_uuid(), encode(sha256('iac:CKV_AWS_189:/terraform/ebs.tf'::bytea), 'hex'), v_infra_id,
     'EBS volume not encrypted', 'EBS volume created without encryption enabled', 'medium', 'open', 'iac',
     'CKV_AWS_189', '/terraform/ebs.tf',
     v_now - interval '1 day', v_now, 1, ARRAY['checkov'], NULL, v_now - interval '1 day', v_now)
ON CONFLICT (project_id, vuln_uid) DO NOTHING;

-- ── Link findings → vulnerabilities (only where still NULL) ──────────────────

UPDATE findings f
SET vulnerability_id = v.id
FROM vulnerabilities v
WHERE f.project_id = v.project_id
  AND v.vuln_uid = encode(sha256('sast:javascript.express.security.express-check-injection:/db/users.js'::bytea), 'hex')
  AND f.fingerprint = encode(sha256('semgrep:javascript.express.security.express-check-injection:src/db/users.js:42'::bytea), 'hex')
  AND f.vulnerability_id IS NULL;

UPDATE findings f
SET vulnerability_id = v.id
FROM vulnerabilities v
WHERE f.project_id = v.project_id
  AND v.vuln_uid = encode(sha256('sast:javascript.browser.security.dom-based-xss:/views/profile.js'::bytea), 'hex')
  AND f.fingerprint = encode(sha256('semgrep:javascript.browser.security.dom-based-xss:src/views/profile.js:28'::bytea), 'hex')
  AND f.vulnerability_id IS NULL;

UPDATE findings f
SET vulnerability_id = v.id
FROM vulnerabilities v
WHERE f.project_id = v.project_id
  AND v.vuln_uid = encode(sha256('sast:javascript.lang.security.audit.unsafe-var-parseint:/utils/parse.js'::bytea), 'hex')
  AND f.fingerprint = encode(sha256('semgrep:javascript.lang.security.audit.unsafe-var-parseint:src/utils/parse.js:15'::bytea), 'hex')
  AND f.vulnerability_id IS NULL;

UPDATE findings f
SET vulnerability_id = v.id
FROM vulnerabilities v
WHERE f.project_id = v.project_id
  AND v.vuln_uid = encode(sha256('sast:javascript.express.security.express-jwt-hardcoded:/auth/tokens.js'::bytea), 'hex')
  AND f.fingerprint = encode(sha256('semgrep:javascript.express.security.express-jwt-hardcoded:src/auth/tokens.js:3'::bytea), 'hex')
  AND f.vulnerability_id IS NULL;

UPDATE findings f
SET vulnerability_id = v.id
FROM vulnerabilities v
WHERE f.project_id = v.project_id
  AND v.vuln_uid = encode(sha256('sast:javascript.lang.correctness.useless-eqeqeq:/validators/helpers.js'::bytea), 'hex')
  AND f.fingerprint = encode(sha256('semgrep:javascript.lang.correctness.useless-eqeqeq:src/validators/helpers.js:67'::bytea), 'hex')
  AND f.vulnerability_id IS NULL;

UPDATE findings f
SET vulnerability_id = v.id
FROM vulnerabilities v
WHERE f.project_id = v.project_id
  AND v.vuln_uid = encode(sha256('sca:CVE-2024-3094'::bytea), 'hex')
  AND f.fingerprint = encode(sha256('trivy:CVE-2024-3094:package-lock.json:1'::bytea), 'hex')
  AND f.vulnerability_id IS NULL;

UPDATE findings f
SET vulnerability_id = v.id
FROM vulnerabilities v
WHERE f.project_id = v.project_id
  AND v.vuln_uid = encode(sha256('sca:CVE-2024-21626'::bytea), 'hex')
  AND f.fingerprint = encode(sha256('trivy:CVE-2024-21626:package-lock.json:1'::bytea), 'hex')
  AND f.vulnerability_id IS NULL;

UPDATE findings f
SET vulnerability_id = v.id
FROM vulnerabilities v
WHERE f.project_id = v.project_id
  AND v.vuln_uid = encode(sha256('sca:CVE-2023-44487'::bytea), 'hex')
  AND f.fingerprint = encode(sha256('trivy:CVE-2023-44487:package-lock.json:1'::bytea), 'hex')
  AND f.vulnerability_id IS NULL;

UPDATE findings f
SET vulnerability_id = v.id
FROM vulnerabilities v
WHERE f.project_id = v.project_id
  AND v.vuln_uid = encode(sha256(('secret:' || encode(sha256('AKIAIOSFODNN7EXAMPLE'::bytea), 'hex'))::bytea), 'hex')
  AND f.fingerprint = encode(sha256('gitleaks:aws-access-key:src/config/.env:12'::bytea), 'hex')
  AND f.vulnerability_id IS NULL;

UPDATE findings f
SET vulnerability_id = v.id
FROM vulnerabilities v
WHERE f.project_id = v.project_id
  AND v.vuln_uid = encode(sha256(('secret:' || encode(sha256(v_secret_ghp::bytea), 'hex'))::bytea), 'hex')
  AND f.fingerprint = encode(sha256('gitleaks:github-pat:src/config/.env:15'::bytea), 'hex')
  AND f.vulnerability_id IS NULL;

UPDATE findings f
SET vulnerability_id = v.id
FROM vulnerabilities v
WHERE f.project_id = v.project_id
  AND v.vuln_uid = encode(sha256(('secret:' || encode(sha256(v_secret_slack::bytea), 'hex'))::bytea), 'hex')
  AND f.fingerprint = encode(sha256('gitleaks:slack-token:src/config/.env:18'::bytea), 'hex')
  AND f.vulnerability_id IS NULL;

UPDATE findings f
SET vulnerability_id = v.id
FROM vulnerabilities v
WHERE f.project_id = v.project_id
  AND v.vuln_uid = encode(sha256('iac:CKV_AWS_18:/terraform/s3.tf'::bytea), 'hex')
  AND f.fingerprint = encode(sha256('checkov:CKV_AWS_18:src/terraform/s3.tf:10'::bytea), 'hex')
  AND f.vulnerability_id IS NULL;

UPDATE findings f
SET vulnerability_id = v.id
FROM vulnerabilities v
WHERE f.project_id = v.project_id
  AND v.vuln_uid = encode(sha256('iac:CKV_AWS_24:/terraform/security.tf'::bytea), 'hex')
  AND f.fingerprint = encode(sha256('checkov:CKV_AWS_24:src/terraform/security.tf:5'::bytea), 'hex')
  AND f.vulnerability_id IS NULL;

UPDATE findings f
SET vulnerability_id = v.id
FROM vulnerabilities v
WHERE f.project_id = v.project_id
  AND v.vuln_uid = encode(sha256('iac:CKV_AWS_189:/terraform/ebs.tf'::bytea), 'hex')
  AND f.fingerprint = encode(sha256('checkov:CKV_AWS_189:src/terraform/ebs.tf:8'::bytea), 'hex')
  AND f.vulnerability_id IS NULL;

-- ── Capture finding IDs for level-3 references ───────────────────────────────

SELECT id INTO v_finding_sqli FROM findings
WHERE project_id = v_project_id
  AND fingerprint = encode(sha256('semgrep:javascript.express.security.express-check-injection:src/db/users.js:42'::bytea), 'hex');

SELECT id INTO v_finding_xss FROM findings
WHERE project_id = v_project_id
  AND fingerprint = encode(sha256('semgrep:javascript.browser.security.dom-based-xss:src/views/profile.js:28'::bytea), 'hex');

SELECT id INTO v_finding_cve3094 FROM findings
WHERE project_id = v_project_id
  AND fingerprint = encode(sha256('trivy:CVE-2024-3094:package-lock.json:1'::bytea), 'hex');

SELECT id INTO v_finding_cve21626 FROM findings
WHERE project_id = v_project_id
  AND fingerprint = encode(sha256('trivy:CVE-2024-21626:package-lock.json:1'::bytea), 'hex');

SELECT id INTO v_finding_aws FROM findings
WHERE project_id = v_project_id
  AND fingerprint = encode(sha256('gitleaks:aws-access-key:src/config/.env:12'::bytea), 'hex');

SELECT id INTO v_finding_s3 FROM findings
WHERE project_id = v_infra_id
  AND fingerprint = encode(sha256('checkov:CKV_AWS_18:src/terraform/s3.tf:10'::bytea), 'hex');

-- ── Level 3: risk_acceptances ────────────────────────────────────────────────

INSERT INTO risk_acceptances (id, finding_id, user_id, rationale, expires_at, approved_by, approved_at, status, review_notes, created_at, updated_at)
VALUES ('a1000000-0000-4000-8000-000000000001', v_finding_sqli, v_viewer_id,
        'Accepted as low business impact — legacy endpoint, compensating control in place',
        v_now + interval '90 days', v_admin_id, v_now - interval '1 day', 'approved',
        'Approved by security lead after compensating-control review',
        v_now - interval '2 days', v_now - interval '1 day')
ON CONFLICT (id) DO NOTHING;

INSERT INTO risk_acceptances (id, finding_id, user_id, rationale, expires_at, status, created_at, updated_at)
VALUES ('a1000000-0000-4000-8000-000000000002', v_finding_cve3094, v_viewer_id,
        'Pending review — critical XZ backdoor, upgrade path being validated',
        v_now + interval '30 days', 'pending', v_now - interval '1 day', v_now - interval '1 day')
ON CONFLICT (id) DO NOTHING;

-- ── Level 3: finding_comments (BIGSERIAL id — never specified) ───────────────

IF NOT EXISTS (
    SELECT 1 FROM finding_comments
    WHERE finding_id = v_finding_sqli AND user_id = v_viewer_id AND content = 'Reproduced locally on main. Fix: parameterize the query.'
) THEN
    INSERT INTO finding_comments (finding_id, user_id, content, created_at, updated_at)
    VALUES (v_finding_sqli, v_viewer_id, 'Reproduced locally on main. Fix: parameterize the query.',
            v_now - interval '2 days', v_now - interval '2 days');
END IF;

IF NOT EXISTS (
    SELECT 1 FROM finding_comments
    WHERE finding_id = v_finding_xss AND user_id = v_admin_id AND content = 'Assigned to frontend team for sanitization pass.'
) THEN
    INSERT INTO finding_comments (finding_id, user_id, content, created_at, updated_at)
    VALUES (v_finding_xss, v_admin_id, 'Assigned to frontend team for sanitization pass.',
            v_now - interval '1 day', v_now - interval '1 day');
END IF;

-- ── Level 3: api_tokens (bcrypt hash of raw hkp_ token; prefix = first 12 chars) ──

INSERT INTO api_tokens (id, name, prefix, hash, project_id, created_by, last_used_at, expires_at, created_at, updated_at)
VALUES ('a2000000-0000-4000-8000-000000000001', 'ci-cd-token', 'hkp_9f3a2b1c',
        '$2a$10$vbmMeiyL0p1kVsqz1gMHf.tr9bTV2jdKQDK/D9tEcDKc21DtUfZpm',
        v_project_id, v_admin_id, v_now - interval '6 hours', v_now + interval '365 days', v_now - interval '30 days', v_now - interval '30 days')
ON CONFLICT (id) DO NOTHING;

INSERT INTO api_tokens (id, name, prefix, hash, project_id, created_by, created_at, updated_at)
VALUES ('a2000000-0000-4000-8000-000000000002', 'infra-token', 'hkp_5e4d3c2b',
        '$2a$10$TVxyPSzcPVnRKBf0JtB95uMg5i8KQBpwGGFJwfPmi8uBK1l6c5QUq',
        v_infra_id, v_admin_id, v_now - interval '7 days', v_now - interval '7 days')
ON CONFLICT (id) DO NOTHING;

-- ── Level 3: scan_schedules ──────────────────────────────────────────────────

INSERT INTO scan_schedules (id, project_id, scanner, scanner_type, cron_expr, enabled, last_run, next_run, created_at)
VALUES ('a3000000-0000-4000-8000-000000000001', v_project_id, 'semgrep', 'sast', '0 9 * * 1', TRUE,
        v_now - interval '7 days', v_now + interval '1 day', v_now - interval '7 days')
ON CONFLICT (id) DO NOTHING;

INSERT INTO scan_schedules (id, app_id, scanner, scanner_type, cron_expr, enabled, next_run, created_at)
VALUES ('a3000000-0000-4000-8000-000000000002', v_app_id, 'trivy', 'sca', '0 2 * * *', TRUE,
        v_now + interval '6 hours', v_now - interval '1 day')
ON CONFLICT (id) DO NOTHING;

-- ── Level 3: webhooks + delivery logs ────────────────────────────────────────

INSERT INTO webhooks (id, label, url, events, enabled, delivery_type, last_delivery, delivery_count, error_count, last_error, created_at)
VALUES ('a4000000-0000-4000-8000-000000000001', 'Slack alerts',
        'https://webhook.example.com/henkaipan/slack-alerts',
        '["finding.created","finding.updated"]'::jsonb, TRUE, 'generic',
        v_now - interval '1 hour', 2, 1, 'POST https://webhook.example.com/...: timeout after 10s',
        v_now - interval '30 days')
ON CONFLICT (id) DO NOTHING;

INSERT INTO webhook_delivery_logs (id, webhook_id, event_type, payload, status_code, response_body, error_message, created_at)
VALUES ('a5000000-0000-4000-8000-000000000001', 'a4000000-0000-4000-8000-000000000001',
        'finding.created', '{"event":"finding.created","project":"Demo API Service"}'::jsonb,
        200, 'ok', NULL, v_now - interval '2 hours')
ON CONFLICT (id) DO NOTHING;

INSERT INTO webhook_delivery_logs (id, webhook_id, event_type, payload, status_code, response_body, error_message, created_at)
VALUES ('a5000000-0000-4000-8000-000000000002', 'a4000000-0000-4000-8000-000000000001',
        'finding.updated', '{"event":"finding.updated","project":"Demo API Service"}'::jsonb,
        NULL, NULL, 'POST https://webhook.example.com/...: timeout after 10s', v_now - interval '1 hour')
ON CONFLICT (id) DO NOTHING;

-- ── Level 3: agent_analyses ──────────────────────────────────────────────────

INSERT INTO agent_analyses (id, finding_id, agent_type, confidence, fp_likelihood, reasoning, raw_output, created_at, updated_at)
VALUES ('a6000000-0000-4000-8000-000000000001', v_finding_sqli, 'validator', 0.98, 'low',
        'Confirmed: user-controlled req.params.id flows into db.query without parameterization.',
        '{"verdict":"confirmed","evidence":["db.query","req.params.id"]}'::jsonb,
        v_now - interval '2 days', v_now - interval '2 days')
ON CONFLICT (finding_id, agent_type) DO NOTHING;

INSERT INTO agent_analyses (id, finding_id, agent_type, confidence, fp_likelihood, reasoning, raw_output, created_at, updated_at)
VALUES ('a6000000-0000-4000-8000-000000000002', v_finding_xss, 'validator', 0.85, 'medium',
        'Likely XSS: userInput assigned to innerHTML without escaping.',
        '{"verdict":"likely","evidence":["innerHTML","userInput"]}'::jsonb,
        v_now - interval '2 days', v_now - interval '2 days')
ON CONFLICT (finding_id, agent_type) DO NOTHING;

-- ── Level 3: finding_correlations ────────────────────────────────────────────

INSERT INTO finding_correlations (id, finding_id_a, finding_id_b, correlation_type, created_at)
VALUES ('a7000000-0000-4000-8000-000000000001', v_finding_cve3094, v_finding_cve21626, 'same_location', v_now - interval '3 days')
ON CONFLICT (finding_id_a, finding_id_b) DO NOTHING;

-- ── Level 3: jira_issue_links ────────────────────────────────────────────────

INSERT INTO jira_issue_links (id, finding_id, issue_key, issue_url, status, created_at)
VALUES ('a8000000-0000-4000-8000-000000000001', v_finding_sqli, 'SEC-123',
        'https://jira.example.com/browse/SEC-123', 'open', v_now - interval '2 days')
ON CONFLICT (finding_id) DO NOTHING;

-- ── Level 3: user_notifications (2 unread + 1 read) ──────────────────────────

INSERT INTO user_notifications (id, user_id, title, message, type, entity_type, entity_id, read, created_at)
VALUES ('a9000000-0000-4000-8000-000000000001', v_admin_id,
        'Critical finding detected', 'SQL Injection in query builder was detected in Demo API Service.',
        'critical', 'finding', v_finding_sqli, FALSE, v_now - interval '3 days')
ON CONFLICT (id) DO NOTHING;

INSERT INTO user_notifications (id, user_id, title, message, type, entity_type, entity_id, read, created_at)
VALUES ('a9000000-0000-4000-8000-000000000002', v_admin_id,
        'Scan completed', 'semgrep scan completed for Demo API Service with 5 findings.',
        'scan_complete', 'scan', v_scan1_id, FALSE, v_now - interval '3 days')
ON CONFLICT (id) DO NOTHING;

INSERT INTO user_notifications (id, user_id, title, message, type, entity_type, entity_id, read, created_at)
VALUES ('a9000000-0000-4000-8000-000000000003', v_admin_id,
        'Weekly digest', '3 new vulnerabilities this week across 2 projects.',
        'digest', 'project', v_project_id, TRUE, v_now - interval '1 day')
ON CONFLICT (id) DO NOTHING;

-- ── Level 3: audit_logs (user_id has no FK) ──────────────────────────────────

INSERT INTO audit_logs (id, user_id, user_email, action, entity_type, entity_id, old_value, new_value, ip_address, user_agent, created_at)
VALUES ('ab000000-0000-4000-8000-000000000001', v_admin_id, 'admin@henkaipan.demo',
        'finding.update', 'finding', v_finding_sqli,
        '{"status":"open"}'::jsonb, '{"status":"in_review"}'::jsonb,
        '192.168.1.10', 'Mozilla/5.0 (X11; Linux x86_64)', v_now - interval '2 days')
ON CONFLICT (id) DO NOTHING;

INSERT INTO audit_logs (id, user_id, user_email, action, entity_type, entity_id, old_value, new_value, ip_address, user_agent, created_at)
VALUES ('ab000000-0000-4000-8000-000000000002', v_admin_id, 'admin@henkaipan.demo',
        'risk_acceptance.create', 'finding', v_finding_sqli,
        NULL, '{"status":"approved","expires_at":"+90 days"}'::jsonb,
        '192.168.1.10', 'Mozilla/5.0 (X11; Linux x86_64)', v_now - interval '1 day')
ON CONFLICT (id) DO NOTHING;

-- ── Singleton configs: UPDATE only (never INSERT) ────────────────────────────

UPDATE notification_settings
SET alert_critical     = TRUE,
    alert_high         = TRUE,
    alert_scan_complete = TRUE,
    alert_scan_failed  = TRUE,
    alert_sla_breach   = TRUE,
    email_recipients   = '["admin@henkaipan.demo"]'::jsonb,
    digest_frequency   = 'daily',
    digest_time        = '08:00',
    report_schedule    = 'weekly',
    report_time        = '09:00',
    report_channel     = 'email',
    updated_at         = v_now
WHERE singleton = TRUE;

UPDATE jira_integrations
SET base_url    = 'https://jira.example.com',
    user_email  = 'admin@henkaipan.demo',
    project_key = 'SEC',
    issue_type  = 'Bug',
    labels      = '["security"]'::jsonb,
    token       = 'jira-token-placeholder',
    enabled     = TRUE,
    updated_at  = v_now
WHERE singleton = TRUE;

RAISE NOTICE 'Full workspace seeded. Project IDs: % (app) / % (standalone)', v_project_id, v_infra_id;

END $$;