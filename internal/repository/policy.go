package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"aspm/internal/models"

	"github.com/jackc/pgx/v5/pgxpool"
)

type policyRepo struct{ db *pgxpool.Pool }

func (r *policyRepo) List(ctx context.Context) ([]models.Policy, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, name, COALESCE(description, ''), conditions, actions, enabled, 
		       COALESCE(pack_type, 'custom'), COALESCE(compliance_controls, '{}'), created_at
		FROM policies ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("policies list: %w", err)
	}
	defer rows.Close()

	var out []models.Policy
	for rows.Next() {
		var p models.Policy
		var condsRaw, actionsRaw []byte
		if err := rows.Scan(&p.ID, &p.Name, &p.Description, &condsRaw, &actionsRaw, &p.Enabled, &p.PackType, &p.ComplianceControls, &p.CreatedAt); err != nil {
			continue
		}
		json.Unmarshal(condsRaw, &p.Conditions)
		json.Unmarshal(actionsRaw, &p.Actions)
		if p.Conditions == nil {
			p.Conditions = []models.PolicyCondition{}
		}
		if p.Actions == nil {
			p.Actions = []models.PolicyAction{}
		}
		if p.ComplianceControls == nil {
			p.ComplianceControls = []string{}
		}
		out = append(out, p)
	}
	return EnsureSlice(out), nil
}

func (r *policyRepo) Create(ctx context.Context, pc PolicyCreate) (*models.Policy, error) {
	condsJSON, _ := json.Marshal(pc.Conditions)
	actionsJSON, _ := json.Marshal(pc.Actions)
	packType := pc.PackType
	if packType == "" {
		packType = "custom"
	}
	controls := pc.ComplianceControls
	if controls == nil {
		controls = []string{}
	}

	var p models.Policy
	var condsRaw, actionsRaw []byte
	err := r.db.QueryRow(ctx, `
		INSERT INTO policies (name, description, conditions, actions, pack_type, compliance_controls)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id, name, COALESCE(description, ''), conditions, actions, enabled, pack_type, compliance_controls, created_at`,
		pc.Name, pc.Description, condsJSON, actionsJSON, packType, controls,
	).Scan(&p.ID, &p.Name, &p.Description, &condsRaw, &actionsRaw, &p.Enabled, &p.PackType, &p.ComplianceControls, &p.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("create policy: %w", err)
	}
	json.Unmarshal(condsRaw, &p.Conditions)
	json.Unmarshal(actionsRaw, &p.Actions)
	return &p, nil
}

func (r *policyRepo) GetByID(ctx context.Context, id string) (*models.Policy, error) {
	var p models.Policy
	var condsRaw, actionsRaw []byte
	err := r.db.QueryRow(ctx, `
		SELECT id, name, COALESCE(description, ''), conditions, actions, enabled,
		       COALESCE(pack_type, 'custom'), COALESCE(compliance_controls, '{}'), created_at
		FROM policies WHERE id = $1`, id,
	).Scan(&p.ID, &p.Name, &p.Description, &condsRaw, &actionsRaw, &p.Enabled, &p.PackType, &p.ComplianceControls, &p.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("get policy: %w", err)
	}
	json.Unmarshal(condsRaw, &p.Conditions)
	json.Unmarshal(actionsRaw, &p.Actions)
	if p.Conditions == nil {
		p.Conditions = []models.PolicyCondition{}
	}
	if p.Actions == nil {
		p.Actions = []models.PolicyAction{}
	}
	if p.ComplianceControls == nil {
		p.ComplianceControls = []string{}
	}
	return &p, nil
}

func (r *policyRepo) SetEnabled(ctx context.Context, id string, enabled bool) error {
	_, err := r.db.Exec(ctx, `UPDATE policies SET enabled=$1 WHERE id=$2`, enabled, id)
	if err != nil {
		return fmt.Errorf("set policy enabled: %w", err)
	}
	return nil
}

func (r *policyRepo) Delete(ctx context.Context, id string) error {
	_, err := r.db.Exec(ctx, `DELETE FROM policies WHERE id=$1`, id)
	if err != nil {
		return fmt.Errorf("delete policy: %w", err)
	}
	return nil
}

func (r *policyRepo) ListActive(ctx context.Context) ([]PolicyRow, error) {
	rows, err := r.db.Query(ctx, `SELECT id, conditions, actions FROM policies WHERE enabled = TRUE`)
	if err != nil {
		return nil, fmt.Errorf("list active policies: %w", err)
	}
	defer rows.Close()

	var out []PolicyRow
	for rows.Next() {
		var pr PolicyRow
		var condsRaw, actionsRaw []byte
		if err := rows.Scan(&pr.ID, &condsRaw, &actionsRaw); err != nil {
			continue
		}
		json.Unmarshal(condsRaw, &pr.Conditions)
		json.Unmarshal(actionsRaw, &pr.Actions)
		out = append(out, pr)
	}
	return out, nil
}

func (r *policyRepo) ExecuteActions(ctx context.Context, findingID string, actions []models.PolicyAction) error {
	for _, a := range actions {
		switch a.Type {
		case "set_status":
			r.db.Exec(ctx, `UPDATE findings SET status=$1 WHERE id=$2`, a.Value, findingID)
		case "assign":
			r.db.Exec(ctx, `UPDATE findings SET assigned_to=$1 WHERE id=$2`, a.Value, findingID)
		}
	}
	return nil
}

func (r *policyRepo) ListSuppressions(ctx context.Context) ([]models.Suppression, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, name, rule_id, file_pattern, scanner, reason, created_at
		FROM suppressions ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("suppressions list: %w", err)
	}
	defer rows.Close()

	var out []models.Suppression
	for rows.Next() {
		var s models.Suppression
		rows.Scan(&s.ID, &s.Name, &s.RuleID, &s.FilePattern, &s.Scanner, &s.Reason, &s.CreatedAt)
		out = append(out, s)
	}
	if out == nil {
		out = []models.Suppression{}
	}
	return out, nil
}

func (r *policyRepo) CreateSuppression(ctx context.Context, sc SuppressionCreate) (*models.Suppression, error) {
	var s models.Suppression
	err := r.db.QueryRow(ctx, `
		INSERT INTO suppressions (name, rule_id, file_pattern, scanner, reason)
		VALUES ($1,$2,$3,$4,$5)
		RETURNING id, name, rule_id, file_pattern, scanner, reason, created_at`,
		sc.Name, sc.RuleID, sc.FilePattern, sc.Scanner, sc.Reason,
	).Scan(&s.ID, &s.Name, &s.RuleID, &s.FilePattern, &s.Scanner, &s.Reason, &s.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("create suppression: %w", err)
	}
	return &s, nil
}

func (r *policyRepo) DeleteSuppression(ctx context.Context, id string) error {
	_, err := r.db.Exec(ctx, `DELETE FROM suppressions WHERE id=$1`, id)
	if err != nil {
		return fmt.Errorf("delete suppression: %w", err)
	}
	return nil
}

func (r *policyRepo) IsSuppressed(ctx context.Context, scanner, ruleID, filePath string) (bool, error) {
	var count int
	err := r.db.QueryRow(ctx, `
		SELECT COUNT(*) FROM suppressions
		WHERE (rule_id      IS NULL OR rule_id = $1)
		  AND (scanner      IS NULL OR scanner = $2)
		  AND (file_pattern IS NULL OR $3 LIKE '%' || file_pattern || '%')
		  AND (rule_id IS NOT NULL OR scanner IS NOT NULL OR file_pattern IS NOT NULL)
		`, ruleID, scanner, filePath).Scan(&count)
	if err != nil {
		slog.Error("suppression check", "err", err)
		return false, err
	}
	return count > 0, nil
}
