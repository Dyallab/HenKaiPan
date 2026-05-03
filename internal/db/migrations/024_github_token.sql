-- Add github_token column for private repo authentication
-- Token is encrypted at rest using SECRET_ENCRYPTION_KEY

ALTER TABLE repos
    ADD COLUMN IF NOT EXISTS github_token TEXT;

CREATE INDEX IF NOT EXISTS idx_repos_has_token
    ON repos(id)
    WHERE github_token IS NOT NULL;

COMMENT ON COLUMN repos.github_token IS 'Encrypted GitHub personal access token for private repo cloning';
