ALTER TABLE findings
    ADD COLUMN IF NOT EXISTS ai_summary TEXT,
    ADD COLUMN IF NOT EXISTS summary_fingerprint TEXT,
    ADD COLUMN IF NOT EXISTS summary_state TEXT NOT NULL DEFAULT 'none';

CREATE INDEX IF NOT EXISTS idx_findings_summary_fingerprint
    ON findings(summary_fingerprint);

CREATE TABLE IF NOT EXISTS finding_summary_cache (
    fingerprint TEXT PRIMARY KEY,
    scanner TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    title TEXT NOT NULL,
    issue_type TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    summary TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
