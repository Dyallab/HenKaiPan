-- Issue #64 MVP (F1+F2): Threat Intel tables
--
-- Introduces `project_dependencies` (declared SCA inventory per project),
-- `threat_advisories` (upstream advisories: GHSA/KEV/CVE feeds), and
-- `project_inventory_hits` (correlation of inventory against advisories with
-- inventory / runtime / match status). Also adds an index on
-- `vulnerabilities(cve_id)` for advisory-to-vulnerability joins.
--
-- Up-only migration (repo convention: migrate.go applies up migrations only,
-- no DOWN sections or down files).

-- Declared dependency inventory per project (SBOM / manifest scan output).
CREATE TABLE IF NOT EXISTS project_dependencies (
    project_id  UUID        NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    ecosystem   TEXT        NOT NULL,
    pkg_name    TEXT        NOT NULL,
    pkg_version TEXT        NOT NULL,
    source_file TEXT,
    declared_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_project_dependencies_lookup
    ON project_dependencies (project_id, ecosystem, pkg_name);

-- Upstream threat advisories (GHSA, CISA KEV, CVE feeds).
CREATE TABLE IF NOT EXISTS threat_advisories (
    advisory_id     TEXT        PRIMARY KEY,
    source          TEXT        NOT NULL,
    cve_id          TEXT,
    ecosystem       TEXT,
    pkg_name        TEXT,
    affected_ranges JSONB,
    severity        TEXT,
    kev             BOOLEAN     NOT NULL DEFAULT FALSE,
    published_at    TIMESTAMPTZ,
    raw             JSONB
);

CREATE INDEX IF NOT EXISTS idx_threat_advisories_cve
    ON threat_advisories (cve_id);
CREATE INDEX IF NOT EXISTS idx_threat_advisories_pkg
    ON threat_advisories (ecosystem, pkg_name);

-- Correlation hits: inventory entries matched against advisories.
CREATE TABLE IF NOT EXISTS project_inventory_hits (
    id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id       UUID        NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    advisory_id      TEXT        NOT NULL REFERENCES threat_advisories(advisory_id) ON DELETE CASCADE,
    pkg_name         TEXT,
    pkg_version      TEXT,
    inventory_status TEXT        NOT NULL CHECK (inventory_status IN ('declared', 'detected', 'corroborated')),
    runtime_status   TEXT        NOT NULL DEFAULT 'L0' CHECK (runtime_status IN ('L0', 'L1', 'L2', 'L3', 'L4')),
    match_status     TEXT        NOT NULL DEFAULT 'unconfirmed' CHECK (match_status IN ('unconfirmed', 'active_threat', 'dismissed')),
    evidence         JSONB,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_project_inventory_hits_project_match
    ON project_inventory_hits (project_id, match_status);

-- Advisory-to-vulnerability join key.
CREATE INDEX IF NOT EXISTS idx_vulns_cve ON vulnerabilities (cve_id);
