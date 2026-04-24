package repository

import (
	"context"
	"fmt"
	"sort"

	"aspm/internal/models"
	"aspm/internal/scanner"

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
		       f.cve_id, f.cwe_id, f.confidence_score, f.corroboration_count, f.suppressed, f.remediation_slug
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
			&fi.CVEID, &fi.CWEID, &fi.ConfidenceScore, &fi.CorroborationCount, &fi.Suppressed, &fi.RemediationSlug)
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
		       cve_id, cwe_id, confidence_score, corroboration_count
		FROM findings WHERE id = $1`, id).
		Scan(&f.ID, &f.ScanID, &f.Scanner, &f.RuleID, &f.Title, &f.Description,
			&f.Severity, &f.FilePath, &f.LineStart, &f.LineEnd, &f.CreatedAt,
			&f.Status, &f.AssignedTo, &f.FalsePositive, &f.Notes, &f.ResolvedAt, &f.SLADeadline,
			&f.CVEID, &f.CWEID, &f.ConfidenceScore, &f.CorroborationCount)
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
		       cve_id, cwe_id, confidence_score, corroboration_count
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
			&f.CVEID, &f.CWEID, &f.ConfidenceScore, &f.CorroborationCount)
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

func (r *findingRepo) RefreshBatchCorrelation(ctx context.Context, findingID string) error {
	current, err := r.getCorrelationContext(ctx, findingID)
	if err != nil {
		return err
	}

	matchedIDs, err := r.findBatchMatches(ctx, current)
	if err != nil {
		return err
	}

	if err := r.replaceCorrelationSet(ctx, findingID, matchedIDs); err != nil {
		return err
	}

	impacted := append([]string{findingID}, matchedIDs...)
	for _, id := range uniqueStrings(impacted) {
		if err := r.recalculateConfidence(ctx, id); err != nil {
			return err
		}
	}
	return nil
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
		       f.cve_id, f.cwe_id, f.confidence_score, f.corroboration_count
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
			&fi.CVEID, &fi.CWEID, &fi.ConfidenceScore, &fi.CorroborationCount)
		findings = append(findings, fi)
	}
	return findings, nil
}

type correlationContext struct {
	FindingID    string
	ScanID       string
	BatchID      string
	Scanner      string
	RuleID       string
	FilePath     string
	LineStart    int
	CVEID        *string
	Suppressed   bool
	ScannerClass scanner.Category
}

func (r *findingRepo) getCorrelationContext(ctx context.Context, findingID string) (*correlationContext, error) {
	var current correlationContext
	err := r.db.QueryRow(ctx, `
		SELECT f.id, f.scan_id, s.scan_batch_id, f.scanner, COALESCE(f.rule_id, ''),
		       COALESCE(f.file_path, ''), COALESCE(f.line_start, 0), f.cve_id, f.suppressed
		FROM findings f
		JOIN scans s ON s.id = f.scan_id
		WHERE f.id = $1`, findingID,
	).Scan(&current.FindingID, &current.ScanID, &current.BatchID, &current.Scanner, &current.RuleID, &current.FilePath, &current.LineStart, &current.CVEID, &current.Suppressed)
	if err != nil {
		return nil, fmt.Errorf("get correlation context: %w", err)
	}
	category, ok := scanner.CategoryFor(current.Scanner)
	if !ok {
		return nil, fmt.Errorf("unknown scanner category: %s", current.Scanner)
	}
	current.ScannerClass = category
	return &current, nil
}

func (r *findingRepo) findBatchMatches(ctx context.Context, current *correlationContext) ([]string, error) {
	if current.Suppressed {
		return nil, nil
	}

	rows, err := r.db.Query(ctx, `
		SELECT f.id, f.scanner
		FROM findings f
		JOIN scans s ON s.id = f.scan_id
		WHERE s.scan_batch_id = $1
		  AND f.id <> $2
		  AND f.suppressed = FALSE
		  AND f.scanner <> $3
		  AND (
				($4 <> '' AND f.rule_id = $4)
				OR ($5 IS NOT NULL AND f.cve_id = $5)
				OR ($6 <> '' AND f.file_path = $6 AND ABS(f.line_start - $7) <= 5)
		  )`,
		current.BatchID, current.FindingID, current.Scanner, current.RuleID, current.CVEID, current.FilePath, current.LineStart,
	)
	if err != nil {
		return nil, fmt.Errorf("query batch matches: %w", err)
	}
	defer rows.Close()

	var ids []string
	for rows.Next() {
		var id string
		var otherScanner string
		if err := rows.Scan(&id, &otherScanner); err != nil {
			return nil, fmt.Errorf("scan batch match: %w", err)
		}
		if !scanner.SameCategory(current.Scanner, otherScanner) {
			continue
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate batch matches: %w", err)
	}
	return uniqueStrings(ids), nil
}

func (r *findingRepo) replaceCorrelationSet(ctx context.Context, findingID string, matchedIDs []string) error {
	if _, err := r.db.Exec(ctx, `
		DELETE FROM finding_correlations
		WHERE correlation_type = 'same_family_batch'
		  AND (finding_id_a = $1 OR finding_id_b = $1)`, findingID); err != nil {
		return fmt.Errorf("clear correlations: %w", err)
	}

	for _, matchedID := range matchedIDs {
		a, b := canonicalPair(findingID, matchedID)
		if _, err := r.db.Exec(ctx, `
			INSERT INTO finding_correlations (finding_id_a, finding_id_b, correlation_type)
			VALUES ($1, $2, 'same_family_batch')
			ON CONFLICT (finding_id_a, finding_id_b) DO UPDATE SET correlation_type = EXCLUDED.correlation_type`, a, b); err != nil {
			return fmt.Errorf("insert correlation: %w", err)
		}
	}
	return nil
}

func (r *findingRepo) recalculateConfidence(ctx context.Context, findingID string) error {
	current, err := r.getCorrelationContext(ctx, findingID)
	if err != nil {
		return err
	}

	rows, err := r.db.Query(ctx, `SELECT scanner FROM scans WHERE scan_batch_id = $1`, current.BatchID)
	if err != nil {
		return fmt.Errorf("list batch scanners: %w", err)
	}
	defer rows.Close()

	peerSet := map[string]struct{}{}
	for rows.Next() {
		var scannerName string
		if err := rows.Scan(&scannerName); err != nil {
			return fmt.Errorf("scan batch scanner: %w", err)
		}
		if scannerName == current.Scanner {
			continue
		}
		if !scanner.SameCategory(current.Scanner, scannerName) {
			continue
		}
		peerSet[scannerName] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate batch scanners: %w", err)
	}

	corroboratedRows, err := r.db.Query(ctx, `
		SELECT DISTINCT other.scanner
		FROM finding_correlations fc
		JOIN findings base ON base.id = $1
		JOIN findings other ON other.id = CASE
			WHEN fc.finding_id_a = base.id THEN fc.finding_id_b
			ELSE fc.finding_id_a
		END
		WHERE fc.correlation_type = 'same_family_batch'
		  AND (fc.finding_id_a = base.id OR fc.finding_id_b = base.id)`, findingID)
	if err != nil {
		return fmt.Errorf("list corroborated scanners: %w", err)
	}
	defer corroboratedRows.Close()

	corroboratedSet := map[string]struct{}{}
	for corroboratedRows.Next() {
		var scannerName string
		if err := corroboratedRows.Scan(&scannerName); err != nil {
			return fmt.Errorf("scan corroborated scanner: %w", err)
		}
		corroboratedSet[scannerName] = struct{}{}
	}
	if err := corroboratedRows.Err(); err != nil {
		return fmt.Errorf("iterate corroborated scanners: %w", err)
	}

	totalPeers := len(peerSet)
	corroboratedCount := len(corroboratedSet)
	score := 0.5
	if totalPeers > 0 && corroboratedCount > 0 {
		score += 0.5 * (float64(corroboratedCount) / float64(totalPeers))
	}
	if score > 1 {
		score = 1
	}

	if _, err := r.db.Exec(ctx, `
		UPDATE findings
		SET confidence_score = $2,
		    corroboration_count = $3
		WHERE id = $1`, findingID, score, corroboratedCount); err != nil {
		return fmt.Errorf("update finding confidence: %w", err)
	}
	return nil
}

func canonicalPair(a, b string) (string, string) {
	if a > b {
		return b, a
	}
	return a, b
}

func uniqueStrings(values []string) []string {
	if len(values) < 2 {
		return values
	}
	seen := make(map[string]struct{}, len(values))
	unique := make([]string, 0, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		unique = append(unique, value)
	}
	sort.Strings(unique)
	return unique
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
