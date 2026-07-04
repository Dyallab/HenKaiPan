ALTER TABLE findings
  ADD COLUMN cve_id TEXT,
  ADD COLUMN cwe_id TEXT;

CREATE INDEX IF NOT EXISTS idx_findings_cve_id ON findings(cve_id) WHERE cve_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_findings_cwe_id ON findings(cwe_id) WHERE cwe_id IS NOT NULL;
