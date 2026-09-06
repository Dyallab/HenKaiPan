-- Issue #64 follow-up (PR #73 duplicate-hits + repeat-notify findings):
-- idempotent hit reconciliation for the 6h threat sync.
--
-- Every sync blind-appended identical project_inventory_hits rows and
-- re-notified on the full set. This migration dedupes pre-existing exact
-- duplicates and adds the unique key ReconcileHits upserts on:
-- (project_id, advisory_id, pkg_name, pkg_version).
--
-- Up-only migration (repo convention: migrate.go applies up migrations only,
-- no DOWN sections or down files).

-- Keep a single row per hit key (NULL-safe compare: pkg_name/pkg_version
-- are nullable, and plain = would never match NULL to NULL).
DELETE FROM project_inventory_hits a
USING project_inventory_hits b
WHERE a.ctid < b.ctid
  AND a.project_id IS NOT DISTINCT FROM b.project_id
  AND a.advisory_id IS NOT DISTINCT FROM b.advisory_id
  AND a.pkg_name IS NOT DISTINCT FROM b.pkg_name
  AND a.pkg_version IS NOT DISTINCT FROM b.pkg_version;

CREATE UNIQUE INDEX IF NOT EXISTS uq_threat_hit
    ON project_inventory_hits (project_id, advisory_id, pkg_name, pkg_version);
