package repository

import (
	"context"
	"fmt"

	"aspm/internal/models"

	"github.com/jackc/pgx/v5/pgxpool"
)

type findingRepo struct{ db *pgxpool.Pool }

func (r *findingRepo) List(ctx context.Context, f FindingFilter) ([]models.Finding, int, error) {
	if f.Page < 1 {
		f.Page = 1
	}
	if f.Limit < 1 || f.Limit > 100 {
		f.Limit = 50
	}
	offset := (f.Page - 1) * f.Limit

	rows, err := r.db.Query(ctx, `
		SELECT f.id, f.scan_id, f.scanner, f.rule_id, f.title, f.description,
		       f.severity, f.file_path, f.line_start, f.line_end, f.created_at,
		       f.status, f.assigned_to, f.false_positive, f.notes, f.resolved_at, f.sla_deadline,
		       f.cve_id, f.cwe_id, f.suppressed, f.remediation_slug
		FROM findings f
		WHERE ($1 = '' OR f.severity = $1)
		  AND ($2 = '' OR f.scanner = $2)
		  AND ($3 = '' OR f.status = $3)
		  AND ($4 = FALSE OR (f.sla_deadline < NOW() AND f.status NOT IN ('fixed','verified','accepted_risk')))
		  AND ($5 = '' OR (
		        ($5 = 'sast'       AND f.scanner IN ('semgrep','gosec')) OR
		        ($5 = 'sca'        AND f.scanner IN ('trivy','grype','osv-scanner')) OR
		        ($5 = 'secrets'    AND f.scanner IN ('trufflehog','gitleaks')) OR
		        ($5 = 'iac'        AND f.scanner IN ('checkov','tfsec','kics')) OR
		        ($5 = 'containers' AND f.scanner IN ('trivy-image','grype-image')) OR
		        ($5 = 'dast'       AND f.scanner IN ('nuclei'))
		      ))
		  AND ($6 = '' OR f.cve_id ILIKE '%' || $6 || '%')
		  AND ($7 = TRUE OR f.suppressed = FALSE)
		ORDER BY
			CASE f.severity
				WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5
			END,
			f.created_at DESC
		LIMIT $8 OFFSET $9`,
		f.Severity, f.Scanner, f.Status, f.Overdue, f.Category, f.CVESearch, f.ShowSuppressed, f.Limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("findings list: %w", err)
	}
	defer rows.Close()

	var findings []models.Finding
	for rows.Next() {
		var fi models.Finding
		rows.Scan(&fi.ID, &fi.ScanID, &fi.Scanner, &fi.RuleID, &fi.Title, &fi.Description,
			&fi.Severity, &fi.FilePath, &fi.LineStart, &fi.LineEnd, &fi.CreatedAt,
			&fi.Status, &fi.AssignedTo, &fi.FalsePositive, &fi.Notes, &fi.ResolvedAt, &fi.SLADeadline,
			&fi.CVEID, &fi.CWEID, &fi.Suppressed, &fi.RemediationSlug)
		findings = append(findings, fi)
	}
	if findings == nil {
		findings = []models.Finding{}
	}

	var total int
	r.db.QueryRow(ctx, `
		SELECT COUNT(*) FROM findings
		WHERE ($1='' OR severity=$1) AND ($2='' OR scanner=$2)
		  AND ($3='' OR status=$3)
		  AND ($4 = FALSE OR (sla_deadline < NOW() AND status NOT IN ('fixed','verified','accepted_risk')))
		  AND ($5 = '' OR (
		        ($5 = 'sast'       AND scanner IN ('semgrep','gosec')) OR
		        ($5 = 'sca'        AND scanner IN ('trivy','grype','osv-scanner')) OR
		        ($5 = 'secrets'    AND scanner IN ('trufflehog','gitleaks')) OR
		        ($5 = 'iac'        AND scanner IN ('checkov','tfsec','kics')) OR
		        ($5 = 'containers' AND scanner IN ('trivy-image','grype-image')) OR
		        ($5 = 'dast'       AND scanner IN ('nuclei'))
		      ))
		  AND ($6 = '' OR cve_id ILIKE '%' || $6 || '%')
		  AND ($7 = TRUE OR suppressed = FALSE)`,
		f.Severity, f.Scanner, f.Status, f.Overdue, f.Category, f.CVESearch, f.ShowSuppressed,
	).Scan(&total)

	return findings, total, nil
}

func (r *findingRepo) GetByID(ctx context.Context, id string) (*models.Finding, error) {
	var f models.Finding
	err := r.db.QueryRow(ctx, `
		SELECT id, scan_id, scanner, rule_id, title, description, severity,
		       file_path, line_start, line_end, created_at,
		       status, assigned_to, false_positive, notes, resolved_at, sla_deadline,
		       cve_id, cwe_id
		FROM findings WHERE id = $1`, id).
		Scan(&f.ID, &f.ScanID, &f.Scanner, &f.RuleID, &f.Title, &f.Description,
			&f.Severity, &f.FilePath, &f.LineStart, &f.LineEnd, &f.CreatedAt,
			&f.Status, &f.AssignedTo, &f.FalsePositive, &f.Notes, &f.ResolvedAt, &f.SLADeadline,
			&f.CVEID, &f.CWEID)
	if err != nil {
		return nil, err
	}
	return &f, nil
}

func (r *findingRepo) GetByScanID(ctx context.Context, scanID string) ([]models.Finding, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, scan_id, scanner, rule_id, title, description, severity,
		       file_path, line_start, line_end, code_snippet, created_at,
		       status, assigned_to, false_positive, notes, resolved_at, sla_deadline,
		       cve_id, cwe_id
		FROM findings WHERE scan_id = $1
		ORDER BY
			CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END,
			created_at`, scanID)
	if err != nil {
		return nil, fmt.Errorf("findings by scan: %w", err)
	}
	defer rows.Close()

	var findings []models.Finding
	for rows.Next() {
		var f models.Finding
		rows.Scan(&f.ID, &f.ScanID, &f.Scanner, &f.RuleID, &f.Title, &f.Description,
			&f.Severity, &f.FilePath, &f.LineStart, &f.LineEnd, &f.CodeSnippet, &f.CreatedAt,
			&f.Status, &f.AssignedTo, &f.FalsePositive, &f.Notes, &f.ResolvedAt, &f.SLADeadline,
			&f.CVEID, &f.CWEID)
		findings = append(findings, f)
	}
	if findings == nil {
		findings = []models.Finding{}
	}
	return findings, nil
}

func (r *findingRepo) Update(ctx context.Context, id string, upd FindingUpdate) (*models.Finding, error) {
	_, err := r.db.Exec(ctx, `
		UPDATE findings SET
			status         = COALESCE($2, status),
			assigned_to    = COALESCE($3, assigned_to),
			false_positive = COALESCE($4, false_positive),
			notes          = COALESCE($5, notes),
			resolved_at    = CASE
				WHEN $2 IN ('fixed','verified') THEN NOW()
				WHEN $2 IS NOT NULL THEN NULL
				ELSE resolved_at
			END
		WHERE id = $1`,
		id, upd.Status, upd.AssignedTo, upd.FalsePositive, upd.Notes)
	if err != nil {
		return nil, fmt.Errorf("update finding: %w", err)
	}
	return r.GetByID(ctx, id)
}

func (r *findingRepo) Insert(ctx context.Context, f FindingInsert) (string, error) {
	var id string
	err := r.db.QueryRow(ctx, `
		INSERT INTO findings
			(scan_id, scanner, rule_id, title, description, severity, file_path, line_start, line_end,
			 code_snippet, raw, sla_deadline, cve_id, cwe_id, suppressed)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
		RETURNING id`,
		f.ScanID, f.Scanner, f.RuleID, f.Title, f.Description,
		f.Severity, f.FilePath, f.LineStart, f.LineEnd,
		f.CodeSnippet, f.Raw, f.SLADeadline, f.CVEID, f.CWEID, f.Suppressed,
	).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("insert finding: %w", err)
	}
	return id, nil
}

func (r *findingRepo) GetSLASummary(ctx context.Context) (*models.SLASummary, error) {
	var s models.SLASummary
	err := r.db.QueryRow(ctx, `
		SELECT
			COUNT(*) FILTER (WHERE sla_deadline < NOW()
			                   AND status NOT IN ('fixed','verified','accepted_risk')) AS overdue,
			COUNT(*) FILTER (WHERE sla_deadline >= NOW()
			                   AND sla_deadline < NOW() + INTERVAL '24 hours'
			                   AND status NOT IN ('fixed','verified','accepted_risk')) AS due_today,
			COUNT(*) FILTER (WHERE sla_deadline >= NOW() + INTERVAL '24 hours'
			                   AND status NOT IN ('fixed','verified','accepted_risk')) AS on_track,
			COUNT(*) FILTER (WHERE sla_deadline IS NULL
			                   AND status NOT IN ('fixed','verified','accepted_risk')) AS no_deadline
		FROM findings`).
		Scan(&s.Overdue, &s.DueToday, &s.OnTrack, &s.NoDeadline)
	if err != nil {
		return nil, fmt.Errorf("sla summary: %w", err)
	}
	return &s, nil
}

func (r *findingRepo) ExportRows(ctx context.Context, f ExportFilter) ([]models.Finding, error) {
	rows, err := r.db.Query(ctx, `
		SELECT f.id, f.scan_id, f.scanner, f.rule_id, f.title, f.description,
		       f.severity, f.file_path, f.line_start, f.created_at,
		       f.status, f.assigned_to, f.false_positive, f.notes, f.resolved_at, f.sla_deadline,
		       f.cve_id, f.cwe_id
		FROM findings f
		WHERE ($1 = '' OR f.severity = $1)
		  AND ($2 = '' OR f.scanner  = $2)
		  AND ($3 = '' OR f.status   = $3)
		ORDER BY
			CASE f.severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END,
			f.created_at DESC`,
		f.Severity, f.Scanner, f.Status)
	if err != nil {
		return nil, fmt.Errorf("export findings: %w", err)
	}
	defer rows.Close()

	var findings []models.Finding
	for rows.Next() {
		var fi models.Finding
		rows.Scan(&fi.ID, &fi.ScanID, &fi.Scanner, &fi.RuleID, &fi.Title, &fi.Description,
			&fi.Severity, &fi.FilePath, &fi.LineStart, &fi.CreatedAt,
			&fi.Status, &fi.AssignedTo, &fi.FalsePositive, &fi.Notes, &fi.ResolvedAt, &fi.SLADeadline,
			&fi.CVEID, &fi.CWEID)
		findings = append(findings, fi)
	}
	return findings, nil
}

func (r *findingRepo) UpdateRemediationSlug(ctx context.Context, findingID, slug string) error {
	_, err := r.db.Exec(ctx,
		`UPDATE findings SET remediation_slug = $1 WHERE id = $2 AND remediation_slug IS NULL`,
		slug, findingID)
	return err
}

func (r *findingRepo) GetForRemediation(ctx context.Context, id string) (*RemediationSource, error) {
	var src RemediationSource
	var cveID, cweID, codeSnippet *string
	err := r.db.QueryRow(ctx, `
		SELECT rule_id, title, description, severity, scanner, file_path, code_snippet, cve_id, cwe_id
		FROM findings WHERE id = $1`, id).
		Scan(&src.RuleID, &src.Title, &src.Description, &src.Severity,
			&src.Scanner, &src.FilePath, &codeSnippet, &cveID, &cweID)
	if err != nil {
		return nil, err
	}
	if cveID != nil {
		src.CVEID = *cveID
	}
	if cweID != nil {
		src.CWEID = *cweID
	}
	if codeSnippet != nil {
		src.CodeSnippet = *codeSnippet
	}
	return &src, nil
}
