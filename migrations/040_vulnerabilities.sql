-- v0.10: Vulnerability Model
--
-- Introduces the `vulnerabilities` table as the canonical entity for real-world
-- security issues. Each vulnerability aggregates findings across scan batches and
-- engines via a deterministic `vuln_uid` computed per engine type.
--
-- Links findings to vulnerabilities (nullable FK — findings without correlation
-- signals remain unlinked until a future backfill).

CREATE TABLE IF NOT EXISTS vulnerabilities (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    vuln_uid        TEXT    NOT NULL,
    project_id      UUID    NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    title           TEXT    NOT NULL,
    description     TEXT,
    severity        TEXT    NOT NULL,
    status          TEXT    NOT NULL DEFAULT 'open',
    engine_type     TEXT    NOT NULL,
    -- Correlation signals (stored for debug / UI, not used in UID computation)
    pkg_name        TEXT,
    pkg_version     TEXT,
    cve_id          TEXT,
    cwe_id          TEXT,
    rule_id         TEXT,
    secret_hash     TEXT,
    file_path       TEXT,
    -- Aggregation
    first_seen_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    finding_count   INT         NOT NULL DEFAULT 1,
    scanner_coverage TEXT[]      NOT NULL DEFAULT '{}',
    confidence_score FLOAT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_vulnerabilities_project_uid UNIQUE (project_id, vuln_uid)
);

CREATE INDEX IF NOT EXISTS idx_vulnerabilities_project    ON vulnerabilities (project_id);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_severity   ON vulnerabilities (severity);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_engine_type ON vulnerabilities (engine_type);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_status      ON vulnerabilities (status);

-- Link findings to vulnerabilities (nullable — existing findings are unlinked until backfill)
ALTER TABLE findings
    ADD COLUMN IF NOT EXISTS vulnerability_id UUID REFERENCES vulnerabilities(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_findings_vulnerability_id ON findings (vulnerability_id);