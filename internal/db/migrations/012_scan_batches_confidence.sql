ALTER TABLE scans
    ADD COLUMN IF NOT EXISTS scan_batch_id UUID;

UPDATE scans
SET scan_batch_id = gen_random_uuid()
WHERE scan_batch_id IS NULL;

ALTER TABLE scans
    ALTER COLUMN scan_batch_id SET NOT NULL;

CREATE INDEX IF NOT EXISTS idx_scans_batch_id
    ON scans(scan_batch_id);

ALTER TABLE findings
    ADD COLUMN IF NOT EXISTS confidence_score FLOAT NOT NULL DEFAULT 0.5,
    ADD COLUMN IF NOT EXISTS corroboration_count INT NOT NULL DEFAULT 0;

CREATE INDEX IF NOT EXISTS idx_findings_confidence_score
    ON findings(confidence_score DESC);
