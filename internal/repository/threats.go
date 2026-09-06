package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"aspm/internal/threats"

	"github.com/jackc/pgx/v5/pgxpool"
)

// ThreatRepository persists threat-intel MVP data (issue #64):
// declared dependency inventory, upstream advisories, and their
// correlation hits, plus the joined exposure listing.
type ThreatRepository interface {
	UpsertDependencies(ctx context.Context, projectID string, deps []threats.Dependency) error
	UpsertAdvisories(ctx context.Context, advs []threats.Advisory, isKEV func(cveID string, aliases []string) bool) error
	InsertHits(ctx context.Context, projectID string, hits []ThreatHit) error
	ReconcileHits(ctx context.Context, projectID string, hits []ThreatHit) ([]ThreatHit, error)
	ListExposures(ctx context.Context, filter ExposureFilter) (rows []ExposureRow, total int, err error)
}

type threatRepo struct{ db *pgxpool.Pool }

// ThreatHit is one inventory↔advisory correlation row to persist.
// NOTE: mirrors the future threats.Hit contract owned by the matcher task;
// kept repository-local so this package never depends on unlanded types.
type ThreatHit struct {
	AdvisoryID      string
	PkgName         string
	PkgVersion      string
	InventoryStatus string // declared | detected | corroborated
	RuntimeStatus   string // L0..L4 (empty = DB default L0)
	MatchStatus     string // unconfirmed | active_threat | dismissed (empty = default)
	Evidence        json.RawMessage
}

// ExposureFilter scopes the exposure listing. Page/Limit default like other
// List methods; Sort must be a whitelisted key (see exposureSorts).
type ExposureFilter struct {
	ProjectID       string
	KEVOnly         bool
	MatchStatus     string
	InventoryStatus string
	Q               string
	Page            int
	Limit           int
	Sort            string
}

// ExposureRow is one hit joined with its advisory columns.
type ExposureRow struct {
	HitID           string     `json:"hit_id"`
	ProjectID       string     `json:"project_id"`
	AdvisoryID      string     `json:"advisory_id"`
	Source          string     `json:"source"`
	CVEID           string     `json:"cve_id"`
	Ecosystem       string     `json:"ecosystem"`
	PkgName         string     `json:"pkg_name"`
	PkgVersion      string     `json:"pkg_version"`
	Severity        string     `json:"severity"`
	KEV             bool       `json:"kev"`
	InventoryStatus string          `json:"inventory_status"`
	RuntimeStatus   string          `json:"runtime_status"`
	MatchStatus     string          `json:"match_status"`
	Evidence        json.RawMessage `json:"evidence,omitempty"`
	PublishedAt     *time.Time      `json:"published_at,omitempty"`
	CreatedAt       time.Time       `json:"created_at"`
}

// exposureSorts whitelists Sort keys to ORDER BY fragments (helpers.go
// DeleteByID whitelist style — never interpolate raw user input).
var exposureSorts = map[string]string{
	"":             "h.created_at DESC",
	"created_at":   "h.created_at DESC",
	"published_at": "a.published_at DESC NULLS LAST, h.created_at DESC",
	"severity": "CASE a.severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 " +
		"WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END, h.created_at DESC",
	"cve_id": "a.cve_id ASC NULLS LAST, h.created_at DESC",
}

// UpsertDependencies replaces the project's declared inventory snapshot.
// The table has no unique constraint, so snapshot replace (DELETE + INSERT
// in one transaction) is the idempotent upsert semantic.
func (r *threatRepo) UpsertDependencies(ctx context.Context, projectID string, deps []threats.Dependency) error {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("upsert dependencies begin: %w", err)
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, `DELETE FROM project_dependencies WHERE project_id = $1`, projectID); err != nil {
		return fmt.Errorf("upsert dependencies clear: %w", err)
	}
	for _, d := range deps {
		if strings.TrimSpace(d.Name) == "" || strings.TrimSpace(d.Version) == "" {
			continue
		}
		var sourceFile *string
		if strings.TrimSpace(d.SourceFile) != "" {
			sourceFile = &d.SourceFile
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO project_dependencies (project_id, ecosystem, pkg_name, pkg_version, source_file)
			VALUES ($1, $2, $3, $4, $5)`,
			projectID, d.Ecosystem, d.Name, d.Version, sourceFile); err != nil {
			return fmt.Errorf("upsert dependencies insert: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("upsert dependencies commit: %w", err)
	}
	return nil
}

// normalizeThreatSeverity maps an advisory to the dashboard enum
// (critical/high/medium/low/info, lowercase). A CVSS score wins when
// available (CVSS>=9 critical, >=7 high, >=4 medium, >0 low); otherwise
// the severity string is accepted only if already a valid enum value
// (case-insensitive) and anything else (e.g. OSV "CVSS_V3" type strings)
// falls back to info.
func normalizeThreatSeverity(sev string, cvss float64) string {
	if cvss >= 9 {
		return "critical"
	}
	if cvss >= 7 {
		return "high"
	}
	if cvss >= 4 {
		return "medium"
	}
	if cvss > 0 {
		return "low"
	}
	switch strings.ToLower(strings.TrimSpace(sev)) {
	case "critical", "high", "medium", "low", "info":
		return strings.ToLower(strings.TrimSpace(sev))
	default:
		return "info"
	}
}

// UpsertAdvisories inserts or refreshes upstream advisories by PK.
// Ecosystem/pkg_name come from the first affected package; affected_ranges
// carries the full per-package ranges as JSONB. kev is ingest-owned: the
// isKEV checker (nil-safe, caller passes threats.IsKEV bound to the KEV
// catalog) decides the flag and it is overwritten on every sync. Severity
// is normalized to the dashboard enum (see normalizeThreatSeverity) so OSV
// type strings like CVSS_V3 never reach the column.
func (r *threatRepo) UpsertAdvisories(ctx context.Context, advs []threats.Advisory, isKEV func(cveID string, aliases []string) bool) error {
	for _, a := range advs {
		if strings.TrimSpace(a.AdvisoryID) == "" {
			continue
		}
		var ecosystem, pkgName *string
		if len(a.AffectedPackages) > 0 {
			if v := strings.TrimSpace(a.AffectedPackages[0].Ecosystem); v != "" {
				ecosystem = &v
			}
			if v := strings.TrimSpace(a.AffectedPackages[0].Name); v != "" {
				pkgName = &v
			}
		}
		var affectedRanges any
		if len(a.AffectedPackages) > 0 {
			if raw, err := json.Marshal(a.AffectedPackages); err == nil {
				affectedRanges = raw
			}
		}
		var raw any
		if len(a.Raw) > 0 {
			raw = a.Raw
		}
		var publishedAt *time.Time
		if !a.Published.IsZero() {
			publishedAt = &a.Published
		}
		kev := false
		if isKEV != nil {
			kev = isKEV(a.CVEID, a.Aliases)
		}
		severity := normalizeThreatSeverity(a.Severity, a.CVSS)
		if _, err := r.db.Exec(ctx, `
			INSERT INTO threat_advisories
				(advisory_id, source, cve_id, ecosystem, pkg_name, affected_ranges, severity, kev, published_at, raw)
			VALUES ($1, $2, NULLIF($3, ''), $4, $5, $6, NULLIF($7, ''), $8, $9, $10)
			ON CONFLICT (advisory_id) DO UPDATE SET
				source          = EXCLUDED.source,
				cve_id          = EXCLUDED.cve_id,
				ecosystem       = EXCLUDED.ecosystem,
				pkg_name        = EXCLUDED.pkg_name,
				affected_ranges = EXCLUDED.affected_ranges,
				severity        = EXCLUDED.severity,
				kev             = EXCLUDED.kev,
				published_at    = EXCLUDED.published_at,
				raw             = EXCLUDED.raw`,
			a.AdvisoryID, a.Source, a.CVEID, ecosystem, pkgName,
			affectedRanges, severity, kev, publishedAt, raw); err != nil {
			return fmt.Errorf("upsert advisory %s: %w", a.AdvisoryID, err)
		}
	}
	return nil
}

// InsertHits persists correlation rows for a project. It delegates to
// ReconcileHits and discards the new-or-changed subset (compat shim for
// callers that persist without notifying).
func (r *threatRepo) InsertHits(ctx context.Context, projectID string, hits []ThreatHit) error {
	_, err := r.ReconcileHits(ctx, projectID, hits)
	return err
}

// ReconcileHits upserts correlation rows idempotently on the uq_threat_hit
// key (project_id, advisory_id, pkg_name, pkg_version) and returns only the
// inserted rows plus rows whose match_status or inventory_status changed —
// the notify candidates. Evidence, inventory and match verdicts are
// overwritten on conflict; runtime_status keeps the highest level ever seen
// (threats.PromoteRuntime refuses downgrades, in which case the stored level
// is kept). Runtime-only changes are persisted but never notify.
func (r *threatRepo) ReconcileHits(ctx context.Context, projectID string, hits []ThreatHit) ([]ThreatHit, error) {
	type priorRow struct {
		inventory string
		runtime   string
		match     string
	}
	prior := map[string]priorRow{}
	rows, err := r.db.Query(ctx, `
		SELECT advisory_id, COALESCE(pkg_name, ''), COALESCE(pkg_version, ''),
			inventory_status, runtime_status, match_status
		FROM project_inventory_hits WHERE project_id = $1`, projectID)
	if err != nil {
		return nil, fmt.Errorf("reconcile hits load prior: %w", err)
	}
	for rows.Next() {
		var advisoryID, pkgName, pkgVersion, inv, run, match string
		if err := rows.Scan(&advisoryID, &pkgName, &pkgVersion, &inv, &run, &match); err != nil {
			continue
		}
		prior[reconcileKey(advisoryID, pkgName, pkgVersion)] = priorRow{inv, run, match}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("reconcile hits scan prior: %w", err)
	}

	var fresh []ThreatHit
	for _, h := range hits {
		if strings.TrimSpace(h.AdvisoryID) == "" {
			continue
		}
		inventoryStatus := h.InventoryStatus
		if inventoryStatus == "" {
			inventoryStatus = "declared"
		}
		runtimeStatus := h.RuntimeStatus
		if runtimeStatus == "" {
			runtimeStatus = "L0"
		}
		matchStatus := h.MatchStatus
		if matchStatus == "" {
			matchStatus = "unconfirmed"
		}
		key := reconcileKey(h.AdvisoryID, h.PkgName, h.PkgVersion)
		prev, existed := prior[key]
		finalRuntime := runtimeStatus
		if existed {
			if promoted, err := threats.PromoteRuntime(
				threats.RuntimeStatus(prev.runtime),
				threats.RuntimeStatus(runtimeStatus)); err == nil {
				finalRuntime = string(promoted)
			} else {
				finalRuntime = prev.runtime
			}
		}
		var evidence any
		if len(h.Evidence) > 0 {
			evidence = h.Evidence
		}
		if _, err := r.db.Exec(ctx, `
			INSERT INTO project_inventory_hits
				(project_id, advisory_id, pkg_name, pkg_version, inventory_status, runtime_status, match_status, evidence)
			VALUES ($1, $2, NULLIF($3, ''), NULLIF($4, ''), $5, $6, $7, $8)
			ON CONFLICT (project_id, advisory_id, pkg_name, pkg_version) DO UPDATE SET
				inventory_status = EXCLUDED.inventory_status,
				runtime_status   = EXCLUDED.runtime_status,
				match_status     = EXCLUDED.match_status,
				evidence         = COALESCE(EXCLUDED.evidence, project_inventory_hits.evidence)`,
			projectID, h.AdvisoryID, h.PkgName, h.PkgVersion,
			inventoryStatus, finalRuntime, matchStatus, evidence); err != nil {
			return nil, fmt.Errorf("reconcile inventory hit %s: %w", h.AdvisoryID, err)
		}
		prior[key] = priorRow{inventoryStatus, finalRuntime, matchStatus}
		if !existed || prev.inventory != inventoryStatus || prev.match != matchStatus {
			fresh = append(fresh, ThreatHit{
				AdvisoryID:      h.AdvisoryID,
				PkgName:         h.PkgName,
				PkgVersion:      h.PkgVersion,
				InventoryStatus: inventoryStatus,
				RuntimeStatus:   finalRuntime,
				MatchStatus:     matchStatus,
				Evidence:        h.Evidence,
			})
		}
	}
	return fresh, nil
}

// reconcileKey mirrors the uq_threat_hit columns with NULL-normalized pkg
// fields (COALESCE in the prior-state query), so map lookups agree with the
// stored rows regardless of NULL vs empty-string representation.
func reconcileKey(advisoryID, pkgName, pkgVersion string) string {
	return advisoryID + "\x00" + pkgName + "\x00" + pkgVersion
}

// ListExposures returns hits joined with advisories, with filters and
// $N-parameterized LIMIT/OFFSET pagination plus the total count.
func (r *threatRepo) ListExposures(ctx context.Context, f ExposureFilter) ([]ExposureRow, int, error) {
	if f.Page < 1 {
		f.Page = 1
	}
	if f.Limit < 1 || f.Limit > 200 {
		f.Limit = 100
	}
	offset := (f.Page - 1) * f.Limit

	where := []string{}
	args := []any{}
	argIdx := 1

	if f.ProjectID != "" {
		where = append(where, fmt.Sprintf("h.project_id = $%d", argIdx))
		args = append(args, f.ProjectID)
		argIdx++
	}

	if f.KEVOnly {
		where = append(where, "a.kev = TRUE")
	}
	if f.MatchStatus != "" {
		where = append(where, fmt.Sprintf("h.match_status = $%d", argIdx))
		args = append(args, f.MatchStatus)
		argIdx++
	}
	if f.InventoryStatus != "" {
		where = append(where, fmt.Sprintf("h.inventory_status = $%d", argIdx))
		args = append(args, f.InventoryStatus)
		argIdx++
	}
	if f.Q != "" {
		where = append(where, fmt.Sprintf(
			"(h.pkg_name ILIKE $%d OR a.cve_id ILIKE $%d OR a.advisory_id ILIKE $%d)",
			argIdx, argIdx, argIdx))
		args = append(args, "%"+f.Q+"%")
		argIdx++
	}
	whereClause := "TRUE"
	if len(where) > 0 {
		whereClause = strings.Join(where, " AND ")
	}

	var total int
	countSQL := `SELECT COUNT(*) FROM project_inventory_hits h
		JOIN threat_advisories a ON a.advisory_id = h.advisory_id WHERE ` + whereClause
	if err := r.db.QueryRow(ctx, countSQL, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count exposures: %w", err)
	}

	sortBy := exposureSorts[f.Sort]
	if sortBy == "" {
		sortBy = exposureSorts[""]
	}
	querySQL := fmt.Sprintf(`
		SELECT h.id, h.project_id, h.advisory_id, a.source,
			COALESCE(a.cve_id, ''), COALESCE(a.ecosystem, ''),
			COALESCE(h.pkg_name, ''), COALESCE(h.pkg_version, ''),
			COALESCE(a.severity, ''), a.kev,
			h.inventory_status, h.runtime_status, h.match_status,
			h.evidence, a.published_at, h.created_at
		FROM project_inventory_hits h
		JOIN threat_advisories a ON a.advisory_id = h.advisory_id
		WHERE %s
		ORDER BY %s
		LIMIT $%d OFFSET $%d`, whereClause, sortBy, argIdx, argIdx+1)
	args = append(args, f.Limit, offset)

	rows, err := r.db.Query(ctx, querySQL, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list exposures: %w", err)
	}
	defer rows.Close()

	var out []ExposureRow
	for rows.Next() {
		var e ExposureRow
		var evidence []byte
		if err := rows.Scan(&e.HitID, &e.ProjectID, &e.AdvisoryID, &e.Source,
			&e.CVEID, &e.Ecosystem, &e.PkgName, &e.PkgVersion, &e.Severity, &e.KEV,
			&e.InventoryStatus, &e.RuntimeStatus, &e.MatchStatus,
			&evidence, &e.PublishedAt, &e.CreatedAt); err != nil {
			continue
		}
		if len(evidence) > 0 {
			e.Evidence = json.RawMessage(evidence)
		}
		out = append(out, e)
	}
	return EnsureSlice(out), total, rows.Err()
}
