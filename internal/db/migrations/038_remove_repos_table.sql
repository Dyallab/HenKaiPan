-- v0.8a: Remove standalone repos table
--
-- Projects are now the primary unit with repo_url directly on the table.
-- The legacy repos table is no longer used — no handlers, no API routes,
-- no nav links. This migration removes it and cleans up foreign keys.

-- ── 1. Drop foreign keys referencing repos ────────────────────────────────

ALTER TABLE scans    DROP CONSTRAINT IF EXISTS scans_repo_id_fkey;
ALTER TABLE projects DROP CONSTRAINT IF EXISTS projects_repo_id_fkey;

-- ── 2. Drop repo_id columns (data migrated to projects.repo_url) ──────────

ALTER TABLE scans    DROP COLUMN IF EXISTS repo_id;
ALTER TABLE projects DROP COLUMN IF EXISTS repo_id;

-- ── 3. Drop the repos table ───────────────────────────────────────────────

DROP TABLE IF EXISTS repos CASCADE;
