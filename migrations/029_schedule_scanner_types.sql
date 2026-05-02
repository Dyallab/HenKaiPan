-- v0.9: Schedule Scanner Types
-- Adds scanner_type column to support pack-based scheduling (e.g. "sast" runs all SAST scanners)

ALTER TABLE scan_schedules 
ADD COLUMN scanner_type VARCHAR(50),
ADD COLUMN IF NOT EXISTS scanner VARCHAR(50);

COMMENT ON COLUMN scan_schedules.scanner_type IS 'Scanner pack/category identifier (sast, sca, secrets, iac, containers, dast). When set, all scanners in the pack are executed.';
COMMENT ON COLUMN scan_schedules.scanner IS 'Individual scanner name for backward compatibility. Used as display value when scanner_type is set.';

CREATE INDEX IF NOT EXISTS idx_scan_schedules_scanner_type ON scan_schedules(scanner_type) WHERE enabled = TRUE;

UPDATE scan_schedules 
SET scanner_type = CASE 
    WHEN scanner IN ('semgrep', 'gosec') THEN 'sast'
    WHEN scanner IN ('trivy', 'grype', 'osv-scanner') THEN 'sca'
    WHEN scanner IN ('trufflehog', 'gitleaks') THEN 'secrets'
    WHEN scanner IN ('checkov', 'tfsec', 'kics') THEN 'iac'
    WHEN scanner IN ('trivy-image', 'grype-image') THEN 'containers'
    WHEN scanner IN ('nuclei') THEN 'dast'
    ELSE NULL
END
WHERE scanner_type IS NULL;
