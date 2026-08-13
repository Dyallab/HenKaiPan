-- SSO user identity linking columns.
-- SSO config (issuer, client ID, client secret, group claims) comes from env vars,
-- matching the AI provider / email / webhook pattern in config.go.
-- SSO_ENABLED env var is the feature gate at startup.
ALTER TABLE users ADD COLUMN IF NOT EXISTS sso_provider TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS sso_subject TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_sso_identity
    ON users (sso_provider, sso_subject)
    WHERE sso_subject IS NOT NULL;
