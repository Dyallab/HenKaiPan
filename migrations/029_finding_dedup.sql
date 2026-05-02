-- v0.8: Finding Deduplication
--
-- Adds project_id and fingerprint to findings for cross-scan dedup.
-- Unique constraint on (project_id, fingerprint) prevents duplicates.

ALTER TABLE findings
    ADD COLUMN IF NOT EXISTS project_id UUID REFERENCES projects(id) ON DELETE SET NULL;

ALTER TABLE findings
    ADD COLUMN IF NOT EXISTS fingerprint TEXT;

-- Backfill project_id from scan
UPDATE findings f
SET project_id = s.project_id
FROM scans s
WHERE s.id = f.scan_id
  AND f.project_id IS NULL;

-- Compute fingerprint for existing findings (same algorithm as Go code)
UPDATE findings
SET fingerprint = ENCODE(
    SHA256((COALESCE(scanner, '') || ':' || COALESCE(rule_id, '') || ':' || COALESCE(file_path, '') || ':' || COALESCE(line_start::text, '0'))::bytea),
    'hex'
)
WHERE fingerprint IS NULL;

-- Enforce uniqueness per project
CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_dedup
    ON findings (project_id, fingerprint)
    WHERE project_id IS NOT NULL AND fingerprint IS NOT NULL;
