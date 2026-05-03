-- Add secret_hash column for correlating secrets by detected value
-- Allows correlation between trufflehog and gitleaks when they find the same secret

ALTER TABLE findings
    ADD COLUMN IF NOT EXISTS secret_hash TEXT;

CREATE INDEX IF NOT EXISTS idx_findings_secret_hash
    ON findings(secret_hash)
    WHERE secret_hash IS NOT NULL;

-- Backfill: compute hash for trufflehog findings (Raw field)
UPDATE findings
SET secret_hash = encode(sha256(
    regexp_replace(raw::text, '.*"Raw"\s*:\s*"([^"]+)".*', '\1')::bytea
), 'hex')
WHERE scanner = 'trufflehog'
  AND secret_hash IS NULL
  AND raw::text LIKE '%Raw%';

-- Backfill: compute hash for gitleaks findings (Match field)
UPDATE findings
SET secret_hash = encode(sha256(
    regexp_replace(raw::text, '.*"Match"\s*:\s*"([^"]+)".*', '\1')::bytea
), 'hex')
WHERE scanner = 'gitleaks'
  AND secret_hash IS NULL
  AND raw::text LIKE '%Match%';
