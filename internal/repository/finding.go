package repository

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"aspm/internal/findings/summarymeta"
	"aspm/internal/models"
	"aspm/internal/scanner"

	"github.com/jackc/pgx/v5"
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
		SELECT f.id, f.scan_id, f.scanner, f.rule_id, f.title, COALESCE(f.description, ''),
		       f.severity, f.file_path, f.line_start, f.line_end, f.created_at,
		       f.status, f.assigned_to, f.false_positive, f.notes, f.resolved_at, f.sla_deadline,
		       f.cve_id, f.cwe_id, f.confidence_score, f.corroboration_count,
		       EXISTS (
		         SELECT 1
		         FROM agent_analyses aa
		         WHERE aa.finding_id = f.id AND aa.agent_type = 'validator'
		       ) AS ai_analyzed,
		       COALESCE(f.ai_summary, ''), f.summary_state, f.suppressed, f.remediation_slug,
		       j.id IS NOT NULL, COALESCE(j.id::text, ''), COALESCE(j.issue_key, ''),
		       COALESCE(j.issue_url, ''), COALESCE(j.status, ''), COALESCE(j.created_at, 'epoch'::timestamptz),
		       COALESCE(f.pkg_name, ''), COALESCE(f.pkg_version, ''),
		       COALESCE((
		         SELECT string_agg(DISTINCT other.scanner, ',')
		         FROM finding_correlations fc
		         JOIN findings other ON other.id = CASE
		           WHEN fc.finding_id_a = f.id THEN fc.finding_id_b
		           ELSE fc.finding_id_a
		         END
		         WHERE fc.correlation_type = 'same_family_batch'
		           AND (fc.finding_id_a = f.id OR fc.finding_id_b = f.id)
		       ), '')
		FROM findings f
		LEFT JOIN jira_issue_links j ON j.finding_id = f.id
		WHERE ($1::text[] IS NULL OR f.severity = ANY($1))
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
		  AND ($10 = '' OR f.file_path = $10)
		ORDER BY
			CASE WHEN $11 = 'confidence_desc' THEN COALESCE(f.confidence_score, 0) END DESC,
			CASE WHEN $11 = 'confidence_asc' THEN COALESCE(f.confidence_score, 0) END ASC,
			CASE WHEN $11 = 'corroborated' THEN f.corroboration_count END DESC,
			`+SeverityOrderSQL+`,
			f.created_at DESC
		LIMIT $8 OFFSET $9`,
		f.Severities, f.Scanner, f.Status, f.Overdue, f.Category, f.CVESearch, f.ShowSuppressed, f.Limit, offset, f.FilePath, f.SortBy)
	if err != nil {
		return nil, 0, fmt.Errorf("findings list: %w", err)
	}
	defer rows.Close()

	var findings []models.Finding
	for rows.Next() {
		var fi models.Finding
		var jiraID, jiraIssueKey, jiraIssueURL, jiraStatus string
		var jiraCreatedAt time.Time
		var hasJiraIssue bool
		if err := rows.Scan(&fi.ID, &fi.ScanID, &fi.Scanner, &fi.RuleID, &fi.Title, &fi.Description,
			&fi.Severity, &fi.FilePath, &fi.LineStart, &fi.LineEnd, &fi.CreatedAt,
			&fi.Status, &fi.AssignedTo, &fi.FalsePositive, &fi.Notes, &fi.ResolvedAt, &fi.SLADeadline,
			&fi.CVEID, &fi.CWEID, &fi.ConfidenceScore, &fi.CorroborationCount, &fi.AIAnalyzed, &fi.AISummary, &fi.SummaryState, &fi.Suppressed, &fi.RemediationSlug,
			&hasJiraIssue, &jiraID, &jiraIssueKey, &jiraIssueURL, &jiraStatus, &jiraCreatedAt,
			&fi.PkgName, &fi.PkgVersion, &fi.CorroboratingScanners); err != nil {
			return nil, 0, fmt.Errorf("scan findings row: %w", err)
		}
		fi.JiraIssue = buildFindingJiraIssue(hasJiraIssue, jiraID, fi.ID, jiraIssueKey, jiraIssueURL, jiraStatus, jiraCreatedAt)
		findings = append(findings, fi)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("findings list rows: %w", err)
	}
	if findings == nil {
		findings = []models.Finding{}
	}

	var total int
	r.db.QueryRow(ctx, `
		SELECT COUNT(*) FROM findings
		WHERE ($1::text[] IS NULL OR severity = ANY($1)) AND ($2='' OR scanner=$2)
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
		  AND ($7 = TRUE OR suppressed = FALSE)
		  AND ($8 = '' OR file_path = $8)`,
		f.Severities, f.Scanner, f.Status, f.Overdue, f.Category, f.CVESearch, f.ShowSuppressed, f.FilePath,
	).Scan(&total)

	return findings, total, nil
}

func (r *findingRepo) ListPendingSLABreaches(ctx context.Context, limit int) ([]SLABreachFinding, error) {
	if limit < 1 || limit > 500 {
		limit = 100
	}
	rows, err := r.db.Query(ctx, `
		SELECT f.id, f.scan_id, s.target, f.severity, f.title, COALESCE(f.rule_id, ''),
		       COALESCE(f.file_path, ''), COALESCE(f.line_start, 0), f.scanner, f.sla_deadline, f.created_at
		FROM findings f
		JOIN scans s ON s.id = f.scan_id
		WHERE f.sla_deadline IS NOT NULL
		  AND f.sla_deadline < NOW()
		  AND f.sla_breach_attempted_at IS NULL
		  AND f.suppressed = FALSE
		  AND f.status NOT IN ('fixed','verified','accepted_risk')
		ORDER BY f.sla_deadline ASC
		LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("list pending sla breaches: %w", err)
	}
	defer rows.Close()

	var findings []SLABreachFinding
	for rows.Next() {
		var finding SLABreachFinding
		if err := rows.Scan(&finding.FindingID, &finding.ScanID, &finding.Repository, &finding.Severity, &finding.Title, &finding.RuleID, &finding.FilePath, &finding.Line, &finding.Scanner, &finding.SLADeadline, &finding.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan sla breach row: %w", err)
		}
		findings = append(findings, finding)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate sla breach rows: %w", err)
	}
	if findings == nil {
		findings = []SLABreachFinding{}
	}
	return findings, nil
}

func (r *findingRepo) MarkSLABreachAttempted(ctx context.Context, findingIDs []string) error {
	if len(findingIDs) == 0 {
		return nil
	}
	_, err := r.db.Exec(ctx, `
		UPDATE findings
		SET sla_breach_attempted_at = $1
		WHERE id::text = ANY($2)`, time.Now().UTC(), findingIDs)
	if err != nil {
		return fmt.Errorf("mark sla breach attempted: %w", err)
	}
	return nil
}

func (r *findingRepo) GetByID(ctx context.Context, id string) (*models.Finding, error) {
	var f models.Finding
	var jiraID, jiraIssueKey, jiraIssueURL, jiraStatus string
	var jiraCreatedAt time.Time
	var hasJiraIssue bool
	err := r.db.QueryRow(ctx, `
		SELECT f.id, f.scan_id, f.scanner, f.rule_id, f.title, COALESCE(f.description, ''), f.severity,
		       f.file_path, f.line_start, f.line_end, f.code_snippet, f.created_at,
		       f.status, f.assigned_to, f.false_positive, f.notes, f.resolved_at, f.sla_deadline,
		       f.cve_id, f.cwe_id, f.confidence_score, f.corroboration_count, COALESCE(f.ai_summary, ''), f.summary_state, f.suppressed, f.remediation_slug,
		       j.id IS NOT NULL, COALESCE(j.id::text, ''), COALESCE(j.issue_key, ''),
		       COALESCE(j.issue_url, ''), COALESCE(j.status, ''), COALESCE(j.created_at, 'epoch'::timestamptz),
		       COALESCE(f.pkg_name, ''), COALESCE(f.pkg_version, '')
		FROM findings f
		LEFT JOIN jira_issue_links j ON j.finding_id = f.id
		WHERE f.id = $1`, id).
		Scan(&f.ID, &f.ScanID, &f.Scanner, &f.RuleID, &f.Title, &f.Description,
			&f.Severity, &f.FilePath, &f.LineStart, &f.LineEnd, &f.CodeSnippet, &f.CreatedAt,
			&f.Status, &f.AssignedTo, &f.FalsePositive, &f.Notes, &f.ResolvedAt, &f.SLADeadline,
			&f.CVEID, &f.CWEID, &f.ConfidenceScore, &f.CorroborationCount, &f.AISummary, &f.SummaryState, &f.Suppressed, &f.RemediationSlug,
			&hasJiraIssue, &jiraID, &jiraIssueKey, &jiraIssueURL, &jiraStatus, &jiraCreatedAt,
			&f.PkgName, &f.PkgVersion)
	if err != nil {
		return nil, err
	}
	f.JiraIssue = buildFindingJiraIssue(hasJiraIssue, jiraID, f.ID, jiraIssueKey, jiraIssueURL, jiraStatus, jiraCreatedAt)
	return &f, nil
}

func buildFindingJiraIssue(hasIssue bool, id, findingID, issueKey, issueURL, status string, createdAt time.Time) *models.JiraIssueLink {
	if !hasIssue {
		return nil
	}
	link := &models.JiraIssueLink{
		ID:        id,
		FindingID: findingID,
		CreatedAt: createdAt,
	}
	if issueKey != "" {
		link.IssueKey = &issueKey
	}
	if issueURL != "" {
		link.IssueURL = &issueURL
	}
	if status != "" {
		link.Status = &status
	}
	return link
}

func (r *findingRepo) GetByScanID(ctx context.Context, scanID string) ([]models.Finding, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, scan_id, scanner, rule_id, title, COALESCE(description, ''), severity,
		       file_path, line_start, line_end, code_snippet, created_at,
		       status, assigned_to, false_positive, notes, resolved_at, sla_deadline,
		       cve_id, cwe_id, confidence_score, corroboration_count, COALESCE(ai_summary, ''), summary_state,
		       COALESCE(pkg_name, ''), COALESCE(pkg_version, '')
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
			&f.CVEID, &f.CWEID, &f.ConfidenceScore, &f.CorroborationCount, &f.AISummary, &f.SummaryState,
			&f.PkgName, &f.PkgVersion)
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
			assigned_to    = CASE WHEN $3 = '' THEN NULL ELSE COALESCE($3, assigned_to) END,
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
			 code_snippet, raw, sla_deadline, cve_id, cwe_id, suppressed, secret_hash, project_id, fingerprint,
			 pkg_name, pkg_version)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)
		ON CONFLICT (project_id, fingerprint) WHERE project_id IS NOT NULL AND fingerprint IS NOT NULL
		DO NOTHING
		RETURNING id`,
		f.ScanID, f.Scanner, f.RuleID, f.Title, f.Description,
		f.Severity, f.FilePath, f.LineStart, f.LineEnd,
		f.CodeSnippet, f.Raw, f.SLADeadline, f.CVEID, f.CWEID, f.Suppressed, f.SecretHash,
		f.ProjectID, f.Fingerprint, f.PkgName, f.PkgVersion,
	).Scan(&id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", nil
		}
		return "", fmt.Errorf("insert finding: %w", err)
	}
	return id, nil
}

func (r *findingRepo) GetSummarySource(ctx context.Context, id string) (*FindingSummarySource, error) {
	var src FindingSummarySource
	err := r.db.QueryRow(ctx, `
		SELECT id, scanner, COALESCE(rule_id, ''), title, COALESCE(description, ''),
		       COALESCE(ai_summary, ''), COALESCE(summary_fingerprint, ''), summary_state,
		       severity, COALESCE(file_path, ''), COALESCE(raw, '{}'::jsonb)
		FROM findings
		WHERE id = $1`, id,
	).Scan(
		&src.FindingID, &src.Scanner, &src.RuleID, &src.Title, &src.Description,
		&src.AISummary, &src.SummaryFingerprint, &src.SummaryState, &src.Severity,
		&src.FilePath, &src.Raw,
	)
	if err != nil {
		return nil, err
	}
	return &src, nil
}

func (r *findingRepo) PrepareAISummary(ctx context.Context, findingID string) (*PreparedSummary, error) {
	src, err := r.GetSummarySource(ctx, findingID)
	if err != nil {
		return nil, fmt.Errorf("get summary source: %w", err)
	}
	if strings.TrimSpace(src.Description) != "" {
		if _, err := r.db.Exec(ctx, `UPDATE findings SET summary_state = 'none' WHERE id = $1`, findingID); err != nil {
			return nil, fmt.Errorf("reset summary state: %w", err)
		}
		return &PreparedSummary{State: "none"}, nil
	}

	meta := summarymeta.Build(src.Scanner, src.RuleID, src.Title, src.Raw)

	var cachedSummary, cachedStatus string
	err = r.db.QueryRow(ctx, `
		SELECT COALESCE(summary, ''), status
		FROM finding_summary_cache
		WHERE fingerprint = $1`, meta.Fingerprint,
	).Scan(&cachedSummary, &cachedStatus)
	if err == nil {
		state := cachedStatus
		if strings.TrimSpace(cachedSummary) != "" {
			state = "ready"
			if _, err := r.db.Exec(ctx, `
				UPDATE findings
				SET summary_fingerprint = $2,
				    ai_summary = $3,
				    summary_state = 'ready'
				WHERE id = $1`, findingID, meta.Fingerprint, cachedSummary,
			); err != nil {
				return nil, fmt.Errorf("apply cached summary: %w", err)
			}
		} else {
			shouldEnqueue := state == "failed"
			if shouldEnqueue {
				state = "pending"
				if _, err := r.db.Exec(ctx, `
					UPDATE finding_summary_cache
					SET status = 'pending',
					    updated_at = NOW()
					WHERE fingerprint = $1`, meta.Fingerprint,
				); err != nil {
					return nil, fmt.Errorf("reset summary cache status: %w", err)
				}
			}
			if _, err := r.db.Exec(ctx, `
				UPDATE findings
				SET summary_fingerprint = $2,
				    summary_state = $3
				WHERE id = $1`, findingID, meta.Fingerprint, state,
			); err != nil {
				return nil, fmt.Errorf("mark summary state: %w", err)
			}
			return &PreparedSummary{Fingerprint: meta.Fingerprint, Summary: cachedSummary, State: state, ShouldEnqueue: shouldEnqueue}, nil
		}
		return &PreparedSummary{Fingerprint: meta.Fingerprint, Summary: cachedSummary, State: state}, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("lookup summary cache: %w", err)
	}

	if _, err := r.db.Exec(ctx, `
		INSERT INTO finding_summary_cache (fingerprint, scanner, rule_id, title, issue_type, status)
		VALUES ($1, $2, $3, $4, $5, 'pending')
		ON CONFLICT (fingerprint) DO NOTHING`,
		meta.Fingerprint, src.Scanner, src.RuleID, src.Title, meta.IssueType,
	); err != nil {
		return nil, fmt.Errorf("insert summary cache: %w", err)
	}

	if _, err := r.db.Exec(ctx, `
		UPDATE findings
		SET summary_fingerprint = $2,
		    summary_state = 'pending'
		WHERE id = $1`, findingID, meta.Fingerprint,
	); err != nil {
		return nil, fmt.Errorf("mark summary pending: %w", err)
	}

	return &PreparedSummary{Fingerprint: meta.Fingerprint, State: "pending", ShouldEnqueue: true}, nil
}

func (r *findingRepo) StoreAISummary(ctx context.Context, fingerprint, summary string) error {
	summary = strings.TrimSpace(summary)
	if summary == "" {
		return fmt.Errorf("empty ai summary")
	}
	if _, err := r.db.Exec(ctx, `
		INSERT INTO finding_summary_cache (fingerprint, scanner, rule_id, title, issue_type, status, summary)
		VALUES ($1, '', '', '', '', 'ready', $2)
		ON CONFLICT (fingerprint) DO UPDATE SET
			summary = EXCLUDED.summary,
			status = 'ready',
			updated_at = NOW()`, fingerprint, summary,
	); err != nil {
		return fmt.Errorf("update summary cache: %w", err)
	}
	if _, err := r.db.Exec(ctx, `
		UPDATE findings
		SET ai_summary = $2,
		    summary_state = 'ready'
		WHERE summary_fingerprint = $1`, fingerprint, summary,
	); err != nil {
		return fmt.Errorf("update findings ai summary: %w", err)
	}
	return nil
}

func (r *findingRepo) MarkAISummaryFailed(ctx context.Context, fingerprint string) error {
	if fingerprint == "" {
		return nil
	}
	if _, err := r.db.Exec(ctx, `
		UPDATE finding_summary_cache
		SET status = 'failed',
		    updated_at = NOW()
		WHERE fingerprint = $1`, fingerprint,
	); err != nil {
		return fmt.Errorf("mark summary cache failed: %w", err)
	}
	if _, err := r.db.Exec(ctx, `
		UPDATE findings
		SET summary_state = 'failed'
		WHERE summary_fingerprint = $1`, fingerprint,
	); err != nil {
		return fmt.Errorf("mark findings summary failed: %w", err)
	}
	return nil
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
		SELECT f.id, f.scan_id, f.scanner, f.rule_id, f.title, COALESCE(f.description, ''),
		       f.severity, f.file_path, f.line_start, f.created_at,
		       f.status, f.assigned_to, f.false_positive, f.notes, f.resolved_at, f.sla_deadline,
		       f.cve_id, f.cwe_id, f.confidence_score, f.corroboration_count,
		       COALESCE(f.pkg_name, ''), COALESCE(f.pkg_version, '')
		FROM findings f
		WHERE ($1::text[] IS NULL OR f.severity = ANY($1))
		  AND ($2 = '' OR f.scanner  = $2)
		  AND ($3 = '' OR f.status   = $3)
		ORDER BY
			CASE f.severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END,
			f.created_at DESC`,
		f.Severities, f.Scanner, f.Status)
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
			&fi.CVEID, &fi.CWEID, &fi.ConfidenceScore, &fi.CorroborationCount,
			&fi.PkgName, &fi.PkgVersion)
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
	SecretHash   string
	Suppressed   bool
	ScannerClass scanner.Category
	PkgName      string
}

func (r *findingRepo) getCorrelationContext(ctx context.Context, findingID string) (*correlationContext, error) {
	var current correlationContext
	err := r.db.QueryRow(ctx, `
		SELECT f.id, f.scan_id, s.scan_batch_id, f.scanner, COALESCE(f.rule_id, ''),
		       COALESCE(f.file_path, ''), COALESCE(f.line_start, 0), f.cve_id, 
		       COALESCE(f.secret_hash, ''), f.suppressed, COALESCE(f.pkg_name, '')
		FROM findings f
		JOIN scans s ON s.id = f.scan_id
		WHERE f.id = $1`, findingID,
	).Scan(&current.FindingID, &current.ScanID, &current.BatchID, &current.Scanner, &current.RuleID, &current.FilePath, &current.LineStart, &current.CVEID, &current.SecretHash, &current.Suppressed, &current.PkgName)
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

	// For IaC scanners, expand line proximity to capture security controls that might be
	// further away in YAML manifests (e.g., allowPrivilegeEscalation:false at line 29 vs missing at line 19)
	isIaC := current.ScannerClass == "iac"
	lineThreshold := 15
	if !isIaC {
		lineThreshold = 5
	}

	// IaC scanners can correlate findings from the same scanner when they reference
	// the same file (e.g., KICS missing attribute correlating with security control)
	sameScannerOK := isIaC

	rows, err := r.db.Query(ctx, `
		SELECT f.id, f.scanner
		FROM findings f
		JOIN scans s ON s.id = f.scan_id
		WHERE s.scan_batch_id = $1
		  AND f.id <> $2
		  AND f.suppressed = FALSE
		  AND ($10 OR f.scanner <> $3)
		  AND (
				-- Secret hash match (strongest correlation for secrets)
				($11 <> '' AND f.secret_hash = $11)
				OR ($4 <> '' AND f.rule_id = $4)
				OR ($5::text IS NOT NULL AND f.cve_id = $5)
				OR ($6 <> '' AND f.file_path = $6 AND ABS(f.line_start - $7) <= $8)
				OR ($12 <> '' AND f.pkg_name = $12)
			)`,
		current.BatchID, current.FindingID, current.Scanner, current.RuleID, current.CVEID, current.FilePath, current.LineStart, lineThreshold, sameScannerOK, current.SecretHash, current.PkgName,
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
	var score *float64
	if totalPeers > 0 && corroboratedCount > 0 {
		calculated := 0.5 + 0.5*(float64(corroboratedCount)/float64(totalPeers))
		if calculated > 1 {
			calculated = 1
		}
		score = &calculated
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

func (r *findingRepo) ListUniqueFiles(ctx context.Context) ([]string, error) {
	rows, err := r.db.Query(ctx, `
		SELECT DISTINCT f.file_path
		FROM findings f
		WHERE f.file_path IS NOT NULL AND f.file_path <> ''
		ORDER BY f.file_path
	`)
	if err != nil {
		return nil, fmt.Errorf("list unique files: %w", err)
	}
	defer rows.Close()

	var files []string
	for rows.Next() {
		var filePath string
		if err := rows.Scan(&filePath); err != nil {
			return nil, fmt.Errorf("scan file path: %w", err)
		}
		files = append(files, filePath)
	}
	if files == nil {
		files = []string{}
	}
	return files, nil
}
