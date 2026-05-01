-- Audit Log: Track all security-relevant changes for compliance evidence
CREATE TABLE IF NOT EXISTS audit_logs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL,
    user_email      TEXT NOT NULL,
    action          TEXT NOT NULL, -- 'finding.update', 'finding.create', 'policy.enable', 'policy.disable', 'suppression.create', 'risk_acceptance.create', etc.
    entity_type     TEXT NOT NULL, -- 'finding', 'policy', 'suppression', 'scan', 'project', 'user'
    entity_id       UUID NOT NULL,
    old_value       JSONB, -- Previous state (null for creates)
    new_value       JSONB, -- New state (null for deletes)
    ip_address      INET,
    user_agent      TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_entity ON audit_logs(entity_type, entity_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at DESC);

-- Risk Acceptances / Exceptions: Formal workflow for accepting security risks
CREATE TABLE IF NOT EXISTS risk_acceptances (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id      UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE, -- Person requesting acceptance
    rationale       TEXT NOT NULL, -- Why this risk is being accepted
    expires_at      TIMESTAMPTZ NOT NULL, -- When this acceptance expires and must be re-reviewed
    approved_by     UUID REFERENCES users(id) ON DELETE SET NULL, -- Admin who approved (null if auto-approved)
    approved_at     TIMESTAMPTZ, -- When it was approved
    status          TEXT NOT NULL DEFAULT 'pending', -- 'pending', 'approved', 'rejected', 'expired'
    review_notes    TEXT, -- Notes from approver
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_risk_acceptances_finding_id ON risk_acceptances(finding_id);
CREATE INDEX IF NOT EXISTS idx_risk_acceptances_status ON risk_acceptances(status);
CREATE INDEX IF NOT EXISTS idx_risk_acceptances_expires_at ON risk_acceptances(expires_at);

-- Add accepted_risk_reason to findings for quick reference
ALTER TABLE findings
    ADD COLUMN IF NOT EXISTS accepted_risk_reason TEXT,
    ADD COLUMN IF NOT EXISTS accepted_risk_expires_at TIMESTAMPTZ;

-- Helper function to update audit_logs.updated_at
CREATE OR REPLACE FUNCTION update_risk_acceptance_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_risk_acceptance_updated_at
    BEFORE UPDATE ON risk_acceptances
    FOR EACH ROW
    EXECUTE FUNCTION update_risk_acceptance_updated_at();

COMMENT ON TABLE audit_logs IS 'Compliance audit trail for all security-relevant changes';
COMMENT ON TABLE risk_acceptances IS 'Formal risk acceptance / exception workflow for compliance';
