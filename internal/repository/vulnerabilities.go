package repository

import (
	"context"
	"fmt"

	"aspm/internal/models"

	"github.com/jackc/pgx/v5/pgxpool"
)

type vulnRepo struct{ db *pgxpool.Pool }

func (r *vulnRepo) List(ctx context.Context, f VulnFilter) ([]models.VulnSummary, int, error) {
	if f.Page < 1 {
		f.Page = 1
	}
	if f.Limit < 1 || f.Limit > 200 {
		f.Limit = 100
	}
	offset := (f.Page - 1) * f.Limit

	query := `SELECT
			COALESCE(f.cve_id, f.rule_id)                       AS vuln_id,
			MIN(f.cve_id)                                        AS cve_id,
			MIN(f.cwe_id)                                        AS cwe_id,
			MIN(f.title)                                         AS title,
			f.severity,
			array_agg(DISTINCT f.scanner)                        AS scanners,
			COUNT(DISTINCT COALESCE(s.repo_id::text, s.target)) AS affected_count,
			COUNT(f.id)                                          AS finding_count,
			COUNT(f.id) FILTER (WHERE f.status NOT IN ('fixed','verified','accepted_risk')) AS open_count,
			COUNT(f.id) FILTER (WHERE f.status IN ('fixed','verified'))                     AS fixed_count
		FROM findings f
		JOIN scans s ON s.id = f.scan_id
		WHERE ($1::text[] IS NULL OR f.severity = ANY($1))
		  AND ($2 = '' OR f.cve_id ILIKE '%'||$2||'%' OR f.rule_id ILIKE '%'||$2||'%' OR f.title ILIKE '%'||$2||'%')
		  AND ($3 = FALSE OR f.status NOT IN ('fixed','verified','accepted_risk'))
		GROUP BY COALESCE(f.cve_id, f.rule_id), f.severity
		ORDER BY
			` + SeverityOrderSQL + `,
			COUNT(DISTINCT COALESCE(s.repo_id::text, s.target)) DESC
		LIMIT $4 OFFSET $5`

	rows, err := r.db.Query(ctx, query,
		f.Severities, f.Search, f.OnlyOpen, f.Limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("vulns list: %w", err)
	}
	defer rows.Close()

	var vulns []models.VulnSummary
	for rows.Next() {
		var v models.VulnSummary
		var scanners []string
		if err := rows.Scan(&v.VulnID, &v.CVEID, &v.CWEID, &v.Title, &v.Severity,
			&scanners, &v.AffectedCount, &v.FindingCount, &v.OpenCount, &v.FixedCount); err != nil {
			continue
		}
		v.Scanners = scanners
		vulns = append(vulns, v)
	}
	vulns = EnsureSlice(vulns)

	var total int
	r.db.QueryRow(ctx, `
		SELECT COUNT(*) FROM (
			SELECT COALESCE(f.cve_id, f.rule_id), f.severity
			FROM findings f
			WHERE ($1::text[] IS NULL OR f.severity = ANY($1))
			  AND ($2 = '' OR f.cve_id ILIKE '%'||$2||'%' OR f.rule_id ILIKE '%'||$2||'%' OR f.title ILIKE '%'||$2||'%')
			  AND ($3 = FALSE OR f.status NOT IN ('fixed','verified','accepted_risk'))
			GROUP BY COALESCE(f.cve_id, f.rule_id), f.severity
		) sub`, f.Severities, f.Search, f.OnlyOpen).Scan(&total)

	return vulns, total, nil
}

func (r *vulnRepo) GetAffected(ctx context.Context, vulnID string) ([]models.AffectedRepo, error) {
	rows, err := r.db.Query(ctx, `
		SELECT
			COALESCE(p.name, split_part(s.target, '/', 5), s.target)  AS repo_name,
			COALESCE(p.repo_url, s.target)                             AS repo_url,
			COUNT(f.id)                                                  AS finding_count,
			COUNT(f.id) FILTER (WHERE f.status NOT IN ('fixed','verified','accepted_risk')) AS open_count,
			COUNT(f.id) FILTER (WHERE f.status IN ('fixed','verified'))                     AS fixed_count,
			array_agg(DISTINCT f.status)                                AS statuses,
			array_remove(array_agg(DISTINCT f.assigned_to), NULL)       AS assignees,
			MIN(f.sla_deadline)::text                                    AS nearest_deadline
		FROM findings f
		JOIN scans s ON s.id = f.scan_id
		LEFT JOIN projects p ON p.id = s.project_id
		WHERE COALESCE(f.cve_id, f.rule_id) = $1
		GROUP BY p.name, p.repo_url, s.target
		ORDER BY open_count DESC, repo_name`,
		vulnID)
	if err != nil {
		return nil, fmt.Errorf("vuln affected: %w", err)
	}
	defer rows.Close()

	var affected []models.AffectedRepo
	for rows.Next() {
		var a models.AffectedRepo
		var statuses, assignees []string
		if err := rows.Scan(&a.RepoName, &a.RepoURL, &a.FindingCount,
			&a.OpenCount, &a.FixedCount, &statuses, &assignees, &a.NearestDeadline); err != nil {
			continue
		}
		a.Statuses = statuses
		a.Assignees = assignees
		affected = append(affected, a)
	}
	return EnsureSlice(affected), nil
}
