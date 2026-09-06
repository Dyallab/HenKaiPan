-- verify-seed.sql — Post-seed integrity assertions for scripts/seed-full.sql
--
-- Every SELECT below returns rows ONLY when a violation exists. A clean run
-- (seed-full.sql applied once or twice — it is idempotent) yields ZERO rows
-- from every assertion SELECT, followed by a summary count block.
--
-- Usage:
--   docker compose exec -T postgres psql -U aspm -d aspm < scripts/verify-seed.sql
--   (pipe via stdin; -f would resolve inside the container, not the host)
--
-- Read-only: contains no INSERT/UPDATE/DELETE.

\echo '=== verify-seed: assertions (rows = violations) ==='

-- ── 1. Seed table row counts ─────────────────────────────────────────────
-- The seed is additive and idempotent, and repository integration tests
-- leave their own rows behind, so every count asserts a MINIMUM (>= N),
-- not an exact value. Section 1b pins the seed's anchor rows by name.

SELECT 'teams: expected >= 1 row' AS violation, count(*) AS actual_count
FROM teams HAVING count(*) < 1;

SELECT 'users: expected >= 2 rows' AS violation, count(*) AS actual_count
FROM users HAVING count(*) < 2;

SELECT 'team_members: expected >= 2 rows' AS violation, count(*) AS actual_count
FROM team_members HAVING count(*) < 2;

SELECT 'apps: expected >= 1 row' AS violation, count(*) AS actual_count
FROM apps HAVING count(*) < 1;

SELECT 'projects: expected >= 2 rows' AS violation, count(*) AS actual_count
FROM projects HAVING count(*) < 2;

SELECT 'scans: expected >= 6 rows' AS violation, count(*) AS actual_count
FROM scans HAVING count(*) < 6;

SELECT 'findings: expected >= 14 rows' AS violation, count(*) AS actual_count
FROM findings HAVING count(*) < 14;

SELECT 'vulnerabilities: expected >= 14 rows' AS violation, count(*) AS actual_count
FROM vulnerabilities HAVING count(*) < 14;

SELECT 'risk_acceptances: expected >= 2 rows' AS violation, count(*) AS actual_count
FROM risk_acceptances HAVING count(*) < 2;

SELECT 'finding_comments: expected >= 2 rows' AS violation, count(*) AS actual_count
FROM finding_comments HAVING count(*) < 2;

SELECT 'api_tokens: expected >= 2 rows' AS violation, count(*) AS actual_count
FROM api_tokens HAVING count(*) < 2;

SELECT 'scan_schedules: expected >= 2 rows' AS violation, count(*) AS actual_count
FROM scan_schedules HAVING count(*) < 2;

SELECT 'webhooks: expected >= 1 row' AS violation, count(*) AS actual_count
FROM webhooks HAVING count(*) < 1;

SELECT 'webhook_delivery_logs: expected >= 2 rows' AS violation, count(*) AS actual_count
FROM webhook_delivery_logs HAVING count(*) < 2;

SELECT 'agent_analyses: expected >= 2 rows' AS violation, count(*) AS actual_count
FROM agent_analyses HAVING count(*) < 2;

SELECT 'finding_correlations: expected >= 1 row' AS violation, count(*) AS actual_count
FROM finding_correlations HAVING count(*) < 1;

SELECT 'jira_issue_links: expected >= 1 row' AS violation, count(*) AS actual_count
FROM jira_issue_links HAVING count(*) < 1;

SELECT 'user_notifications: expected >= 3 rows' AS violation, count(*) AS actual_count
FROM user_notifications HAVING count(*) < 3;

-- ── 1b. Seed anchor rows (must exist by name) ───────────────────────────────

SELECT 'missing seed team Security Team' AS violation
WHERE NOT EXISTS (SELECT 1 FROM teams WHERE name = 'Security Team');

SELECT 'missing seed user admin' AS violation
WHERE NOT EXISTS (SELECT 1 FROM users WHERE username = 'admin' AND role = 'admin');

SELECT 'missing seed user viewer' AS violation
WHERE NOT EXISTS (SELECT 1 FROM users WHERE username = 'viewer' AND role = 'viewer');

SELECT 'missing seed app Demo App' AS violation
WHERE NOT EXISTS (SELECT 1 FROM apps WHERE name = 'Demo App');

SELECT 'missing seed project Demo API Service' AS violation
WHERE NOT EXISTS (SELECT 1 FROM projects WHERE name = 'Demo API Service' AND app_id IS NOT NULL);

SELECT 'missing seed project Demo Infra' AS violation
WHERE NOT EXISTS (SELECT 1 FROM projects WHERE name = 'Demo Infra' AND app_id IS NULL);

-- audit_logs also receives rows from app usage; seed guarantees at least its 2.
SELECT 'audit_logs: expected >= 2 rows' AS violation, count(*) AS actual_count
FROM audit_logs HAVING count(*) < 2;

-- ── 2. Findings with orphan vulnerability_id (LEFT JOIN NULL) ─────────────────

SELECT 'finding with orphan vulnerability_id' AS violation,
       f.id, f.project_id, f.fingerprint
FROM findings f
LEFT JOIN vulnerabilities v ON v.id = f.vulnerability_id
WHERE v.id IS NULL;

-- ── 3. Duplicate fingerprints per project ─────────────────────────────────────

SELECT 'duplicate (project_id, fingerprint)' AS violation,
       project_id, fingerprint, count(*) AS dup_count
FROM findings
WHERE fingerprint IS NOT NULL
GROUP BY project_id, fingerprint
HAVING count(*) > 1;

-- ── 4. Scans without scan_batch_id ────────────────────────────────────────────

SELECT 'scan without scan_batch_id' AS violation,
       id, project_id, scanner, status
FROM scans
WHERE scan_batch_id IS NULL;

-- ── 5. Users with role outside (admin, viewer) ────────────────────────────────

SELECT 'user with invalid role' AS violation,
       id, username, role
FROM users
WHERE role NOT IN ('admin', 'viewer');

-- ── 6. Orphan team_members ────────────────────────────────────────────────────

SELECT 'orphan team_member' AS violation,
       tm.team_id, tm.user_id
FROM team_members tm
LEFT JOIN teams t ON t.id = tm.team_id
LEFT JOIN users u ON u.id = tm.user_id
WHERE t.id IS NULL OR u.id IS NULL;

-- ── 7. finding_comments with empty content ────────────────────────────────────

SELECT 'finding_comment with empty content' AS violation,
       id, finding_id, user_id
FROM finding_comments
WHERE content IS NULL OR btrim(content) = '';

-- ── 8. Singleton configs must have exactly 1 row ──────────────────────────────

SELECT 'notification_settings: expected exactly 1 row' AS violation,
       count(*) AS actual_count
FROM notification_settings
HAVING count(*) <> 1;

SELECT 'jira_integrations: expected exactly 1 row' AS violation,
       count(*) AS actual_count
FROM jira_integrations
HAVING count(*) <> 1;

-- ── 9. api_tokens without hash ────────────────────────────────────────────────

SELECT 'api_token without hash' AS violation,
       id, name, prefix
FROM api_tokens
WHERE hash IS NULL OR btrim(hash) = '';

-- ── 10. scan_schedules without cron_expr ──────────────────────────────────────

SELECT 'scan_schedule without cron_expr' AS violation,
       id, scanner, scanner_type
FROM scan_schedules
WHERE cron_expr IS NULL OR btrim(cron_expr) = '';

-- ── Summary counts ────────────────────────────────────────────────────────────

\echo '=== verify-seed: summary counts ==='

SELECT 'teams'              AS table_name, count(*) AS row_count FROM teams
UNION ALL SELECT 'users',              count(*) FROM users
UNION ALL SELECT 'team_members',       count(*) FROM team_members
UNION ALL SELECT 'apps',               count(*) FROM apps
UNION ALL SELECT 'projects',           count(*) FROM projects
UNION ALL SELECT 'scans',              count(*) FROM scans
UNION ALL SELECT 'findings',           count(*) FROM findings
UNION ALL SELECT 'vulnerabilities',    count(*) FROM vulnerabilities
UNION ALL SELECT 'risk_acceptances',   count(*) FROM risk_acceptances
UNION ALL SELECT 'finding_comments',   count(*) FROM finding_comments
UNION ALL SELECT 'api_tokens',         count(*) FROM api_tokens
UNION ALL SELECT 'scan_schedules',     count(*) FROM scan_schedules
UNION ALL SELECT 'webhooks',           count(*) FROM webhooks
UNION ALL SELECT 'webhook_delivery_logs', count(*) FROM webhook_delivery_logs
UNION ALL SELECT 'agent_analyses',     count(*) FROM agent_analyses
UNION ALL SELECT 'finding_correlations', count(*) FROM finding_correlations
UNION ALL SELECT 'jira_issue_links',   count(*) FROM jira_issue_links
UNION ALL SELECT 'user_notifications', count(*) FROM user_notifications
UNION ALL SELECT 'audit_logs',         count(*) FROM audit_logs
UNION ALL SELECT 'notification_settings', count(*) FROM notification_settings
UNION ALL SELECT 'jira_integrations',  count(*) FROM jira_integrations
ORDER BY table_name;

\echo '=== verify-seed: done (any rows above the summary are violations) ==='