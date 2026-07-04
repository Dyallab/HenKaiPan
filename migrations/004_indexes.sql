CREATE INDEX IF NOT EXISTS idx_findings_created_at       ON findings(created_at);
CREATE INDEX IF NOT EXISTS idx_findings_severity_status  ON findings(severity, status);
