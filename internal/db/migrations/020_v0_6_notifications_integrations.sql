ALTER TABLE notification_settings
    ADD COLUMN IF NOT EXISTS alert_sla_breach BOOLEAN NOT NULL DEFAULT TRUE;

ALTER TABLE findings
    ADD COLUMN IF NOT EXISTS sla_breach_attempted_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_findings_sla_breach_pending
    ON findings (sla_deadline)
    WHERE sla_breach_attempted_at IS NULL
      AND sla_deadline IS NOT NULL
      AND status NOT IN ('fixed', 'verified', 'accepted_risk');
