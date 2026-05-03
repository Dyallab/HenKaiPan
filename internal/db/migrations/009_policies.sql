ALTER TABLE findings ADD COLUMN IF NOT EXISTS suppressed BOOLEAN NOT NULL DEFAULT FALSE;

CREATE TABLE IF NOT EXISTS policies (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT        NOT NULL,
    conditions  JSONB       NOT NULL DEFAULT '[]',
    actions     JSONB       NOT NULL DEFAULT '[]',
    enabled     BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS suppressions (
    id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    name         TEXT        NOT NULL,
    rule_id      TEXT,
    file_pattern TEXT,
    scanner      TEXT,
    reason       TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_policies_enabled    ON policies(enabled);
CREATE INDEX IF NOT EXISTS idx_findings_suppressed ON findings(suppressed);
