-- Cleanup script - Remove vulnerabilities, scans, and findings only
-- Keeps: users, teams, apps, projects, policies, schedules, notifications, webhooks, etc.
-- 
-- Usage:
--   docker compose exec -T postgres psql -U aspm -d aspm < scripts/cleanup-data.sql
--
-- OR from inside container:
--   psql -U aspm -d aspm -f /docker-entrypoint-initdb.d/scripts/cleanup-data.sql

BEGIN;

-- Order matters due to foreign key dependencies
-- findings references vulnerabilities (vulnerability_id FK)
-- vulnerabilities has findings via FK relationship

-- Use CASCADE to handle foreign key dependencies
TRUNCATE TABLE vulnerabilities, findings, scans CASCADE;

COMMIT;

-- Verify cleanup
SELECT 
    'findings' as table_name, COUNT(*) as row_count FROM findings
UNION ALL SELECT 'scans', COUNT(*) FROM scans
UNION ALL SELECT 'vulnerabilities', COUNT(*) FROM vulnerabilities
ORDER BY table_name;
