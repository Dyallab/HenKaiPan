-- v1.8.0: API Tokens for CI/CD Integration
-- Tokens allow external systems (GitHub Actions, GitLab CI, etc.) to
-- authenticate against the API without a user JWT session.

CREATE TABLE api_tokens (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT NOT NULL,
    prefix      TEXT NOT NULL,                     -- e.g. "hkp_" prefix for identification
    hash        TEXT NOT NULL,                     -- bcrypt hash of the token value
    project_id  UUID REFERENCES projects(id) ON DELETE CASCADE,
    created_by  UUID REFERENCES users(id) ON DELETE SET NULL,
    last_used_at TIMESTAMPTZ,
    expires_at  TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- A token without project_id can be used against any project the creator owns.
-- A token with project_id is scoped to that project only.
CREATE INDEX idx_api_tokens_prefix ON api_tokens(prefix);
CREATE INDEX idx_api_tokens_project_id ON api_tokens(project_id);
CREATE INDEX idx_api_tokens_created_by ON api_tokens(created_by);

COMMENT ON TABLE api_tokens IS 'API tokens for CI/CD and external tool authentication';
COMMENT ON COLUMN api_tokens.prefix IS 'First few characters of the raw token for UI identification (e.g. hkp_abc...)';
COMMENT ON COLUMN api_tokens.hash IS 'Bcrypt hash of the full token value — plain token is only shown at creation time';
COMMENT ON COLUMN api_tokens.project_id IS 'When set, the token is scoped to this project only. NULL means any project the user owns';
COMMENT ON COLUMN api_tokens.expires_at IS 'Optional expiration date. NULL means the token never expires';
