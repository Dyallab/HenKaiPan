-- NO TRANSACTION
-- SSO user identity linking columns.
-- SSO config (issuer, client ID, client secret, group claims) comes from env vars,
-- matching the AI provider / email / webhook pattern in config.go.
-- SSO_ENABLED env var is the feature gate at startup.
ALTER TABLE users ADD COLUMN IF NOT EXISTS sso_provider TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS sso_subject TEXT;
ALTER TABLE users ADD CONSTRAINT users_sso_pair_check CHECK (
    (sso_provider IS NULL AND sso_subject IS NULL)
    OR (sso_provider IS NOT NULL AND sso_subject IS NOT NULL)
);
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS idx_users_sso_identity
    ON users (sso_provider, sso_subject)
    WHERE sso_provider IS NOT NULL AND sso_subject IS NOT NULL;
