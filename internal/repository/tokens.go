package repository

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

const (
	tokenPrefix  = "hkp_"
	tokenByteLen = 32 // 64 hex chars
)

type tokenRepo struct {
	db *pgxpool.Pool
}

func NewTokenRepository(db *pgxpool.Pool) TokenRepository {
	return &tokenRepo{db: db}
}

// generateToken creates a cryptographically random token "hkp_<hex>".
func generateToken() (raw string, prefix string, err error) {
	b := make([]byte, tokenByteLen)
	if _, err := rand.Read(b); err != nil {
		return "", "", fmt.Errorf("rand read: %w", err)
	}
	raw = tokenPrefix + hex.EncodeToString(b)
	prefix = raw[:12] // e.g. "hkp_abc123de"
	return raw, prefix, nil
}

func hashToken(raw string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(raw), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("bcrypt: %w", err)
	}
	return string(b), nil
}

func (r *tokenRepo) Create(ctx context.Context, tok TokenCreate, hash, prefix string) (*Token, error) {
	row := r.db.QueryRow(ctx,
		`INSERT INTO api_tokens (name, hash, prefix, project_id, created_by, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6)
		 RETURNING id, name, prefix, project_id, created_by, last_used_at, expires_at, created_at, updated_at`,
		tok.Name, hash, prefix, tok.ProjectID, tok.CreatedBy, tok.ExpiresAt,
	)

	t := &Token{}
	if err := row.Scan(
		&t.ID, &t.Name, &t.Prefix, &t.ProjectID, &t.CreatedBy,
		&t.LastUsedAt, &t.ExpiresAt, &t.CreatedAt, &t.UpdatedAt,
	); err != nil {
		return nil, fmt.Errorf("insert token: %w", err)
	}
	return t, nil
}

func (r *tokenRepo) List(ctx context.Context, userID string) ([]Token, error) {
	rows, err := r.db.Query(ctx,
		`SELECT id, name, prefix, project_id, created_by, last_used_at, expires_at, created_at, updated_at
		 FROM api_tokens
		 WHERE created_by = $1
		 ORDER BY created_at DESC`, userID,
	)
	if err != nil {
		return nil, fmt.Errorf("list tokens: %w", err)
	}
	defer rows.Close()

	var tokens []Token
	for rows.Next() {
		var t Token
		if err := rows.Scan(
			&t.ID, &t.Name, &t.Prefix, &t.ProjectID, &t.CreatedBy,
			&t.LastUsedAt, &t.ExpiresAt, &t.CreatedAt, &t.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan token: %w", err)
		}
		tokens = append(tokens, t)
	}
	return tokens, rows.Err()
}

// GetByPrefix looks up a token by its prefix (e.g. "hkp_abc123de").
// Returns the stored hash so the caller can verify the full raw token.
func (r *tokenRepo) GetByPrefix(ctx context.Context, prefix string) (*Token, error) {
	row := r.db.QueryRow(ctx,
		`SELECT id, name, hash, prefix, project_id, created_by, last_used_at, expires_at, created_at, updated_at
		 FROM api_tokens
		 WHERE prefix = $1`, prefix,
	)

	t := &Token{}
	var hash string
	if err := row.Scan(
		&t.ID, &t.Name, &hash, &t.Prefix, &t.ProjectID, &t.CreatedBy,
		&t.LastUsedAt, &t.ExpiresAt, &t.CreatedAt, &t.UpdatedAt,
	); err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("get token by prefix: %w", err)
	}
	t.Hash = hash // internal, not serialized
	return t, nil
}

// VerifyToken checks a raw token against a bcrypt hash.
func VerifyToken(raw, hash string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(raw)) == nil
}

func (r *tokenRepo) Delete(ctx context.Context, id, userID string) error {
	tag, err := r.db.Exec(ctx,
		`DELETE FROM api_tokens WHERE id = $1 AND created_by = $2`, id, userID,
	)
	if err != nil {
		return fmt.Errorf("delete token: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

func (r *tokenRepo) UpdateLastUsed(ctx context.Context, id string) error {
	_, err := r.db.Exec(ctx,
		`UPDATE api_tokens SET last_used_at = NOW() WHERE id = $1`, id,
	)
	return err
}

// compile-time interface check
var _ TokenRepository = (*tokenRepo)(nil)
