-- v0.8a: Domain Reset — Projects as primary asset, Apps optional grouping
--
-- Key changes:
-- 1. Projects table gets repo connection fields (becomes self-sufficient)
-- 2. app_id becomes nullable (standalone projects allowed)
-- 3. scans table gets project_id (rewire scans to projects)
-- 4. Backfill existing data

-- ── 1. Add repo connection fields to projects ──────────────────────────────

ALTER TABLE projects
    ADD COLUMN IF NOT EXISTS repo_url TEXT,
    ADD COLUMN IF NOT EXISTS provider VARCHAR(20) DEFAULT 'git',
    ADD COLUMN IF NOT EXISTS default_branch VARCHAR(255) DEFAULT 'main',
    ADD COLUMN IF NOT EXISTS github_token_encrypted BYTEA,
    ADD COLUMN IF NOT EXISTS external_repo_id TEXT;

-- ── 2. Backfill projects with repo data ────────────────────────────────────

UPDATE projects p SET
    repo_url        = r.url,
    provider        = 'git',
    default_branch  = 'main'
FROM repos r
WHERE r.id = p.repo_id
  AND p.repo_url IS NULL;

-- ── 3. Make app_id nullable (standalone projects) ─────────────────────────

-- First drop the NOT NULL constraint
ALTER TABLE projects
    ALTER COLUMN app_id DROP NOT NULL;

-- Drop the UNIQUE(app_id, name) constraint — we'll replace it
-- We need to find the constraint name first
DO $$
DECLARE
    constraint_name TEXT;
BEGIN
    SELECT conname INTO constraint_name
    FROM pg_constraint
    WHERE conrelid = 'projects'::regclass
      AND contype = 'u'
      AND conkey::int[] @> ARRAY[
          (SELECT attnum FROM pg_attribute WHERE attrelid = 'projects'::regclass AND attname = 'app_id')
      ];
    IF constraint_name IS NOT NULL THEN
        EXECUTE format('ALTER TABLE projects DROP CONSTRAINT %I', constraint_name);
    END IF;
END $$;

-- Add new unique constraint: name must be unique only when app_id is set
-- For standalone projects (app_id NULL), we need a different approach
-- Use a partial unique index instead
CREATE UNIQUE INDEX IF NOT EXISTS idx_projects_app_name
    ON projects (app_id, name)
    WHERE app_id IS NOT NULL;

-- Standalone projects need unique names globally
CREATE UNIQUE INDEX IF NOT EXISTS idx_projects_standalone_name
    ON projects (name)
    WHERE app_id IS NULL;

-- ── 4. Add project_id to scans ─────────────────────────────────────────────

ALTER TABLE scans
    ADD COLUMN IF NOT EXISTS project_id UUID REFERENCES projects(id) ON DELETE SET NULL;

-- Backfill: link existing scans to their project via repo_id
UPDATE scans s SET project_id = p.id
FROM projects p
WHERE p.repo_id = s.repo_id
  AND s.project_id IS NULL;

-- Also try matching by target URL for scans that might not have repo_id set
UPDATE scans s SET project_id = p.id
FROM projects p
WHERE p.repo_url = s.target
  AND s.project_id IS NULL;

-- Create index for project-based queries
CREATE INDEX IF NOT EXISTS idx_scans_project_id ON scans(project_id);

-- ── 5. Add indexes ────────────────────────────────────────────────────────

CREATE INDEX IF NOT EXISTS idx_projects_repo_url ON projects(repo_url);
CREATE INDEX IF NOT EXISTS idx_projects_provider ON projects(provider);
