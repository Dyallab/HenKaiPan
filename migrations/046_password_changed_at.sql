-- Add token_version to users for JWT session invalidation on password/role change.
-- Every time a password or role is changed, increment token_version to invalidate
-- all existing JWT tokens issued before the change.
ALTER TABLE users ADD COLUMN IF NOT EXISTS token_version INTEGER NOT NULL DEFAULT 0;
