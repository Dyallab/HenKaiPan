-- v0.8a: Token security hardening
--
-- 1. Drop legacy plaintext github_token from repos table (unused, security risk)
-- 2. Add github_token_expires_at to projects for PAT expiry tracking

-- ── 1. Remove legacy plaintext token from repos ────────────────────────────

ALTER TABLE repos DROP COLUMN IF EXISTS github_token;
DROP INDEX IF EXISTS idx_repos_has_token;

-- ── 2. Add token expiry tracking to projects ───────────────────────────────

ALTER TABLE projects
    ADD COLUMN IF NOT EXISTS github_token_expires_at TIMESTAMPTZ;

COMMENT ON COLUMN projects.github_token_expires_at IS 'GitHub PAT expiry timestamp (from X-OAuth-Scopes header validation)';
