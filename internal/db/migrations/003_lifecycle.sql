ALTER TABLE findings
  ADD COLUMN status        VARCHAR(20)  NOT NULL DEFAULT 'open',
  ADD COLUMN assigned_to   TEXT,
  ADD COLUMN false_positive BOOLEAN     NOT NULL DEFAULT FALSE,
  ADD COLUMN notes         TEXT,
  ADD COLUMN resolved_at   TIMESTAMPTZ,
  ADD COLUMN sla_deadline  TIMESTAMPTZ;

UPDATE findings SET sla_deadline = CASE
  WHEN severity = 'critical' THEN created_at + INTERVAL '24 hours'
  WHEN severity = 'high'     THEN created_at + INTERVAL '72 hours'
  WHEN severity = 'medium'   THEN created_at + INTERVAL '30 days'
  WHEN severity = 'low'      THEN created_at + INTERVAL '90 days'
  ELSE NULL END;

CREATE INDEX idx_findings_status       ON findings(status);
CREATE INDEX idx_findings_sla_deadline ON findings(sla_deadline);
