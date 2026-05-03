ALTER TABLE notification_settings ADD COLUMN IF NOT EXISTS alert_sla_breach BOOLEAN NOT NULL DEFAULT true;
