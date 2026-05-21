-- v0.9: SCA Package Correlation
--
-- Adds pkg_name and pkg_version to findings for cross-scanner SCA matching.
-- Enables correlation when different scanners report the same package vulnerability
-- with different IDs (e.g. GHSA-xxx vs CVE-xxx).

ALTER TABLE findings
    ADD COLUMN IF NOT EXISTS pkg_name TEXT;

ALTER TABLE findings
    ADD COLUMN IF NOT EXISTS pkg_version TEXT;

CREATE INDEX IF NOT EXISTS idx_findings_pkg
    ON findings (pkg_name, pkg_version)
    WHERE pkg_name IS NOT NULL;
