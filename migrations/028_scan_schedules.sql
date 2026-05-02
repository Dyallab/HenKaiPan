-- v0.8: Scan Scheduling
--
-- Allows users to define cron-based periodic scans per project.
-- The worker checks due schedules on a 1-minute tick and enqueues scan jobs.

CREATE TABLE IF NOT EXISTS scan_schedules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    scanner VARCHAR(50) NOT NULL,
    cron_expr VARCHAR(100) NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    last_run TIMESTAMPTZ,
    next_run TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_scan_schedules_project_id ON scan_schedules(project_id);
CREATE INDEX IF NOT EXISTS idx_scan_schedules_next_run ON scan_schedules(next_run) WHERE enabled = TRUE;

COMMENT ON TABLE scan_schedules IS 'Periodic scan definitions per project';
COMMENT ON COLUMN scan_schedules.cron_expr IS 'Standard 5-field cron syntax (e.g. "0 9 * * 1" = every Monday 9am)';
COMMENT ON COLUMN scan_schedules.scanner IS 'Scanner type identifier matching the scanner registry';
