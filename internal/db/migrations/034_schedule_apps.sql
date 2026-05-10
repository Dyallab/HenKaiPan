-- v0.10: Schedule App Support
-- Adds app_id column so schedules can target entire apps (all projects in the app).

ALTER TABLE scan_schedules
ADD COLUMN IF NOT EXISTS app_id UUID REFERENCES apps(id) ON DELETE CASCADE;

ALTER TABLE scan_schedules
ALTER COLUMN project_id DROP NOT NULL;

CREATE INDEX IF NOT EXISTS idx_scan_schedules_app_id ON scan_schedules(app_id);

COMMENT ON COLUMN scan_schedules.app_id IS 'When set, the schedule targets all projects belonging to this app. Mutually exclusive with project_id.';
