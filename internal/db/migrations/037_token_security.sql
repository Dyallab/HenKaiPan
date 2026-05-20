-- v0.8a: Token security hardening
--
-- Add github_token_expires_at to projects for PAT expiry tracking

-- ── Add token expiry tracking to projects ──────────────────────────────

ALTER TABLE projects
    ADD COLUMN IF NOT EXISTS github_token_expires_at TIMESTAMPTZ;

COMMENT ON COLUMN projects.github_token_expires_at IS 'GitHub PAT expiry timestamp (from X-OAuth-Scopes header validation)';
