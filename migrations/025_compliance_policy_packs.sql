-- Add compliance_controls column to policies for framework mapping
ALTER TABLE policies
    ADD COLUMN IF NOT EXISTS compliance_controls TEXT[] NOT NULL DEFAULT '{}';

ALTER TABLE policies
    ADD COLUMN IF NOT EXISTS description TEXT NOT NULL DEFAULT '';

ALTER TABLE policies
    ADD COLUMN IF NOT EXISTS pack_type TEXT NOT NULL DEFAULT 'custom';

CREATE INDEX IF NOT EXISTS idx_policies_pack_type ON policies(pack_type);
CREATE INDEX IF NOT EXISTS idx_policies_compliance_controls ON policies USING GIN(compliance_controls);

-- Seed SOC2 Starter Pack policies
INSERT INTO policies (id, name, description, conditions, actions, enabled, pack_type, compliance_controls, created_at)
VALUES
    -- CC6.1: Logical Access Controls - Secrets detection
    (
        gen_random_uuid(),
        'No Secrets in Code',
        'Automatically marks secrets detected by scanners as high priority and assigns to security lead.',
        '[{"field":"scanner","op":"eq","value":"trufflehog"},{"field":"scanner","op":"eq","value":"gitleaks"}]'::jsonb,
        '[{"type":"set_status","value":"in_review"}]'::jsonb,
        TRUE,
        'soc2-starter',
        ARRAY['CC6.1', 'A.9.4.1', 'REQ 3.5'],
        NOW()
    ),
    
    -- CC7.1: Vulnerability Management - Auto-triage criticals
    (
        gen_random_uuid(),
        'Auto-Triage Critical Vulnerabilities',
        'Automatically assigns critical severity findings to security team for immediate review.',
        '[{"field":"severity","op":"eq","value":"critical"}]'::jsonb,
        '[{"type":"set_status","value":"in_review"}]'::jsonb,
        TRUE,
        'soc2-starter',
        ARRAY['CC7.1', 'A.12.6.1', 'REQ 6.3.3'],
        NOW()
    ),
    
    -- CC6.3: Secure Coding Practices - SAST findings
    (
        gen_random_uuid(),
        'SAST Findings Review Required',
        'Marks all SAST findings as in-review to ensure code vulnerabilities are assessed.',
        '[{"field":"scanner","op":"eq","value":"semgrep"},{"field":"scanner","op":"eq","value":"gosec"}]'::jsonb,
        '[{"type":"set_status","value":"in_review"}]'::jsonb,
        TRUE,
        'soc2-starter',
        ARRAY['CC6.3', 'A.14.2.1', 'REQ 6.2.4'],
        NOW()
    ),
    
    -- CC8.1: Change Management - IaC security
    (
        gen_random_uuid(),
        'IaC Security Review',
        'Ensures all infrastructure-as-code findings are reviewed before deployment.',
        '[{"field":"scanner","op":"eq","value":"checkov"},{"field":"scanner","op":"eq","value":"tfsec"},{"field":"scanner","op":"eq","value":"kics"}]'::jsonb,
        '[{"type":"set_status","value":"in_review"}]'::jsonb,
        TRUE,
        'soc2-starter',
        ARRAY['CC8.1', 'A.12.1.2', 'REQ 6.4'],
        NOW()
    ),
    
    -- A1.2: Availability Monitoring - DAST findings
    (
        gen_random_uuid(),
        'DAST Findings Monitoring',
        'Tracks external vulnerability scans for availability and security monitoring.',
        '[{"field":"scanner","op":"eq","value":"nuclei"}]'::jsonb,
        '[{"type":"set_status","value":"in_review"}]'::jsonb,
        TRUE,
        'soc2-starter',
        ARRAY['A1.2', 'A.11.1.1', 'REQ 11.3'],
        NOW()
    ),

    -- ISO 27001: Malicious code protection
    (
        gen_random_uuid(),
        'Malicious Code Detection',
        'Monitors for patterns indicating malicious code or backdoors.',
        '[{"field":"rule_id","op":"contains","value":"backdoor"},{"field":"rule_id","op":"contains","value":"malware"}]'::jsonb,
        '[{"type":"set_status","value":"in_review"}]'::jsonb,
        TRUE,
        'iso27001-basics',
        ARRAY['A.12.2.1', 'CC6.1'],
        NOW()
    ),

    -- ISO 27001: Risk management high severity
    (
        gen_random_uuid(),
        'High Risk Findings Escalation',
        'Escalates high severity findings for risk assessment.',
        '[{"field":"severity","op":"eq","value":"high"}]'::jsonb,
        '[{"type":"assign","value":"security-team"}]'::jsonb,
        TRUE,
        'iso27001-basics',
        ARRAY['A.12.6.1', 'CC7.1'],
        NOW()
    );

-- Create index for compliance_controls array
COMMENT ON COLUMN policies.compliance_controls IS 'Array of compliance control IDs (e.g., CC6.1, A.12.6.1, REQ 3.5) mapped from SOC2, ISO 27001, PCI-DSS';
COMMENT ON COLUMN policies.pack_type IS 'Policy pack type: custom, soc2-starter, iso27001-basics';
