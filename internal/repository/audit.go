package repository

import (
	"context"
	"encoding/json"
	"fmt"

	"aspm/internal/models"

	"github.com/jackc/pgx/v5/pgxpool"
)

type auditRepo struct{ db *pgxpool.Pool }

type AuditLogEntry struct {
	UserID    string
	UserEmail string
	Action    string
	EntityType string
	EntityID  string
	OldValue  any
	NewValue  any
	IPAddress string
	UserAgent string
}

func (r *auditRepo) Log(ctx context.Context, entry AuditLogEntry) error {
	var oldJSON, newJSON []byte
	var err error

	if entry.OldValue != nil {
		oldJSON, err = json.Marshal(entry.OldValue)
		if err != nil {
			return fmt.Errorf("marshal old value: %w", err)
		}
	}
	if entry.NewValue != nil {
		newJSON, err = json.Marshal(entry.NewValue)
		if err != nil {
			return fmt.Errorf("marshal new value: %w", err)
		}
	}

	// Postgres INET rejects empty strings; pass nil instead
	var ipAddr any = entry.IPAddress
	if ipAddr.(string) == "" {
		ipAddr = nil
	}
	var userAgent any = entry.UserAgent
	if userAgent.(string) == "" {
		userAgent = nil
	}

	_, err = r.db.Exec(ctx, `
		INSERT INTO audit_logs (user_id, user_email, action, entity_type, entity_id, old_value, new_value, ip_address, user_agent)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		entry.UserID, entry.UserEmail, entry.Action, entry.EntityType, entry.EntityID, oldJSON, newJSON, ipAddr, userAgent)
	return err
}

func (r *auditRepo) List(ctx context.Context, filter AuditFilter) ([]models.AuditLog, int, error) {
	if filter.Page < 1 {
		filter.Page = 1
	}
	if filter.Limit < 1 || filter.Limit > 100 {
		filter.Limit = 50
	}
	offset := (filter.Page - 1) * filter.Limit

	rows, err := r.db.Query(ctx, `
		SELECT id, user_id, user_email, action, entity_type, entity_id,
		       old_value, new_value, COALESCE(ip_address::text, ''), COALESCE(user_agent, ''), created_at
		FROM audit_logs
		WHERE ($1 = '' OR user_id::text = $1)
		  AND ($2 = '' OR entity_type = $2)
		  AND ($3 = '' OR action = $3)
		ORDER BY created_at DESC
		LIMIT $4 OFFSET $5`,
		filter.UserID, filter.EntityType, filter.Action, filter.Limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("audit list: %w", err)
	}
	defer rows.Close()

	var logs []models.AuditLog
	for rows.Next() {
		var log models.AuditLog
		var oldRaw, newRaw []byte
		if err := rows.Scan(&log.ID, &log.UserID, &log.UserEmail, &log.Action, &log.EntityType, &log.EntityID, &oldRaw, &newRaw, &log.IPAddress, &log.UserAgent, &log.CreatedAt); err != nil {
			return nil, 0, fmt.Errorf("audit scan: %w", err)
		}
		if oldRaw != nil {
			json.Unmarshal(oldRaw, &log.OldValue)
		}
		if newRaw != nil {
			json.Unmarshal(newRaw, &log.NewValue)
		}
		logs = append(logs, log)
	}
	if logs == nil {
		logs = []models.AuditLog{}
	}

	var total int
	r.db.QueryRow(ctx, `
		SELECT COUNT(*) FROM audit_logs
		WHERE ($1 = '' OR user_id::text = $1)
		  AND ($2 = '' OR entity_type = $2)
		  AND ($3 = '' OR action = $3)`,
		filter.UserID, filter.EntityType, filter.Action).Scan(&total)

	return logs, total, nil
}

type riskAcceptanceRepo struct{ db *pgxpool.Pool }

func (r *riskAcceptanceRepo) Create(ctx context.Context, req RiskAcceptanceCreate) (*models.RiskAcceptance, error) {
	var ra models.RiskAcceptance
	err := r.db.QueryRow(ctx, `
		INSERT INTO risk_acceptances (finding_id, user_id, rationale, expires_at, status)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, finding_id, user_id, rationale, expires_at, approved_by, approved_at, status, review_notes, created_at, updated_at`,
		req.FindingID, req.UserID, req.Rationale, req.ExpiresAt, req.Status).Scan(
		&ra.ID, &ra.FindingID, &ra.UserID, &ra.Rationale, &ra.ExpiresAt, &ra.ApprovedBy, &ra.ApprovedAt, &ra.Status, &ra.ReviewNotes, &ra.CreatedAt, &ra.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("create risk acceptance: %w", err)
	}
	return &ra, nil
}

func (r *riskAcceptanceRepo) GetByFindingID(ctx context.Context, findingID string) (*models.RiskAcceptance, error) {
	var ra models.RiskAcceptance
	err := r.db.QueryRow(ctx, `
		SELECT id, finding_id, user_id, rationale, expires_at, approved_by, approved_at, status, review_notes, created_at, updated_at
		FROM risk_acceptances
		WHERE finding_id = $1
		ORDER BY created_at DESC
		LIMIT 1`, findingID).Scan(
		&ra.ID, &ra.FindingID, &ra.UserID, &ra.Rationale, &ra.ExpiresAt, &ra.ApprovedBy, &ra.ApprovedAt, &ra.Status, &ra.ReviewNotes, &ra.CreatedAt, &ra.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &ra, nil
}

func (r *riskAcceptanceRepo) Approve(ctx context.Context, id, approvedBy, reviewNotes string) error {
	_, err := r.db.Exec(ctx, `
		UPDATE risk_acceptances
		SET approved_by = $2, approved_at = NOW(), status = 'approved', review_notes = $3, updated_at = NOW()
		WHERE id = $1`, id, approvedBy, reviewNotes)
	return err
}

func (r *riskAcceptanceRepo) Reject(ctx context.Context, id, reviewNotes string) error {
	_, err := r.db.Exec(ctx, `
		UPDATE risk_acceptances
		SET status = 'rejected', review_notes = $2, updated_at = NOW()
		WHERE id = $1`, id, reviewNotes)
	return err
}

func (r *riskAcceptanceRepo) Expire(ctx context.Context) error {
	_, err := r.db.Exec(ctx, `
		UPDATE risk_acceptances
		SET status = 'expired', updated_at = NOW()
		WHERE status = 'approved' AND expires_at < NOW()`)
	return err
}

func (r *riskAcceptanceRepo) List(ctx context.Context, filter RiskAcceptanceFilter) ([]models.RiskAcceptance, int, error) {
	if filter.Page < 1 {
		filter.Page = 1
	}
	if filter.Limit < 1 || filter.Limit > 100 {
		filter.Limit = 50
	}
	offset := (filter.Page - 1) * filter.Limit

	rows, err := r.db.Query(ctx, `
		SELECT id, finding_id, user_id, rationale, expires_at, approved_by, approved_at, status, review_notes, created_at, updated_at
		FROM risk_acceptances
		WHERE ($1::text IS NULL OR status = $1)
		  AND ($2::uuid IS NULL OR finding_id = $2)
		ORDER BY created_at DESC
		LIMIT $3 OFFSET $4`,
		filter.Status, filter.FindingID, filter.Limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("risk acceptance list: %w", err)
	}
	defer rows.Close()

	var ras []models.RiskAcceptance
	for rows.Next() {
		var ra models.RiskAcceptance
		if err := rows.Scan(&ra.ID, &ra.FindingID, &ra.UserID, &ra.Rationale, &ra.ExpiresAt, &ra.ApprovedBy, &ra.ApprovedAt, &ra.Status, &ra.ReviewNotes, &ra.CreatedAt, &ra.UpdatedAt); err != nil {
			return nil, 0, err
		}
		ras = append(ras, ra)
	}
	if ras == nil {
		ras = []models.RiskAcceptance{}
	}

	var total int
	r.db.QueryRow(ctx, `
		SELECT COUNT(*) FROM risk_acceptances
		WHERE ($1::text IS NULL OR status = $1)
		  AND ($2::uuid IS NULL OR finding_id = $2)`,
		filter.Status, filter.FindingID).Scan(&total)

	return ras, total, nil
}
