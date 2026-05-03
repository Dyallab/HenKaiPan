-- Add index on findings.assigned_to for faster lookups
-- Note: assigned_to remains TEXT to allow external assignments, 
-- but we validate against users.username and teams.name in the application layer
CREATE INDEX IF NOT EXISTS idx_findings_assigned_to ON findings(assigned_to);
