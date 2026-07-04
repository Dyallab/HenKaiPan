package repository

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	"aspm/internal/models"
)

type agentRepo struct{ db *pgxpool.Pool }

func (r *agentRepo) GetAnalysis(ctx context.Context, findingID, agentType string) (*models.AgentAnalysis, error) {
	var a models.AgentAnalysis
	err := r.db.QueryRow(ctx, `
		SELECT id, finding_id, agent_type, confidence, fp_likelihood,
		       COALESCE(reasoning, ''), raw_output, created_at, updated_at
		FROM agent_analyses
		WHERE finding_id = $1 AND agent_type = $2
	`, findingID, agentType).Scan(
		&a.ID, &a.FindingID, &a.AgentType, &a.Confidence, &a.FPLikelihood,
		&a.Reasoning, &a.RawOutput, &a.CreatedAt, &a.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &a, nil
}

func (r *agentRepo) UpsertAnalysis(ctx context.Context, ins AgentAnalysisInsert) (*models.AgentAnalysis, error) {
	var a models.AgentAnalysis
	err := r.db.QueryRow(ctx, `
		INSERT INTO agent_analyses (finding_id, agent_type, confidence, fp_likelihood, reasoning, raw_output)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (finding_id, agent_type) DO UPDATE SET
			confidence    = EXCLUDED.confidence,
			fp_likelihood = EXCLUDED.fp_likelihood,
			reasoning     = EXCLUDED.reasoning,
			raw_output    = EXCLUDED.raw_output,
			updated_at    = NOW()
		RETURNING id, finding_id, agent_type, confidence, fp_likelihood,
		          COALESCE(reasoning, ''), raw_output, created_at, updated_at
	`, ins.FindingID, ins.AgentType, ins.Confidence, ins.FPLikelihood, ins.Reasoning, ins.RawOutput).Scan(
		&a.ID, &a.FindingID, &a.AgentType, &a.Confidence, &a.FPLikelihood,
		&a.Reasoning, &a.RawOutput, &a.CreatedAt, &a.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &a, nil
}

func (r *agentRepo) GetCorrelatedFindings(ctx context.Context, findingID string) ([]models.Finding, error) {
	rows, err := r.db.Query(ctx, `
		SELECT DISTINCT f2.id, f2.scan_id, f2.scanner, f2.rule_id, f2.title, f2.description,
		       f2.severity, f2.file_path, f2.line_start, f2.line_end,
		       COALESCE(f2.code_snippet, ''), f2.created_at, f2.status,
		       f2.assigned_to, f2.false_positive, f2.notes, f2.resolved_at,
		       f2.sla_deadline, f2.cve_id, f2.cwe_id, f2.suppressed, f2.remediation_slug
		FROM findings f1
		JOIN findings f2 ON (
			f2.id != f1.id AND f2.suppressed = false AND (
				(f2.rule_id = f1.rule_id AND f2.scanner != f1.scanner)
				OR (f2.file_path = f1.file_path AND f1.file_path != ''
				    AND ABS(f2.line_start - f1.line_start) <= 5
				    AND f2.scanner != f1.scanner)
				OR (f1.cve_id IS NOT NULL AND f2.cve_id = f1.cve_id)
			)
		)
		WHERE f1.id = $1
		LIMIT 20
	`, findingID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var findings []models.Finding
	for rows.Next() {
		var f models.Finding
		if err := rows.Scan(
			&f.ID, &f.ScanID, &f.Scanner, &f.RuleID, &f.Title, &f.Description,
			&f.Severity, &f.FilePath, &f.LineStart, &f.LineEnd, &f.CodeSnippet,
			&f.CreatedAt, &f.Status, &f.AssignedTo, &f.FalsePositive, &f.Notes,
			&f.ResolvedAt, &f.SLADeadline, &f.CVEID, &f.CWEID, &f.Suppressed, &f.RemediationSlug,
		); err != nil {
			return nil, err
		}
		findings = append(findings, f)
	}
	return findings, rows.Err()
}

func (r *agentRepo) InsertCorrelations(ctx context.Context, findingID string, correlatedIDs []string, correlationType string) error {
	for _, cid := range correlatedIDs {
		// canonical order: smaller UUID first to satisfy UNIQUE constraint
		a, b := findingID, cid
		if a > b {
			a, b = b, a
		}
		_, err := r.db.Exec(ctx, `
			INSERT INTO finding_correlations (finding_id_a, finding_id_b, correlation_type)
			VALUES ($1, $2, $3)
			ON CONFLICT (finding_id_a, finding_id_b) DO NOTHING
		`, a, b, correlationType)
		if err != nil {
			return err
		}
	}
	return nil
}

var _ AgentRepository = (*agentRepo)(nil)
