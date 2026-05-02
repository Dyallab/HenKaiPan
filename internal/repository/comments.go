package repository

import (
	"context"
	"fmt"
	"time"
)

type CommentCreate struct {
	FindingID string
	UserID    string
	Content   string
}

type FindingComment struct {
	ID        int64     `json:"id"`
	FindingID string    `json:"finding_id"`
	UserID    string    `json:"user_id"`
	Username  string    `json:"username"`
	Content   string    `json:"content"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (r *appRepo) GetFindingComments(ctx context.Context, findingID string) ([]FindingComment, error) {
	rows, err := r.db.Query(ctx, `
		SELECT fc.id, fc.finding_id, fc.user_id, u.username, fc.content, fc.created_at, fc.updated_at
		FROM finding_comments fc
		JOIN users u ON u.id = fc.user_id
		WHERE fc.finding_id = $1
		ORDER BY fc.created_at ASC
	`, findingID)
	if err != nil {
		return nil, fmt.Errorf("get finding comments: %w", err)
	}
	defer rows.Close()

	var comments []FindingComment
	for rows.Next() {
		var c FindingComment
		err := rows.Scan(&c.ID, &c.FindingID, &c.UserID, &c.Username, &c.Content, &c.CreatedAt, &c.UpdatedAt)
		if err != nil {
			return nil, fmt.Errorf("scan comment: %w", err)
		}
		comments = append(comments, c)
	}
	return EnsureSlice(comments), nil
}

func (r *appRepo) CreateFindingComment(ctx context.Context, c CommentCreate) (*FindingComment, error) {
	var comment FindingComment
	err := r.db.QueryRow(ctx, `
		INSERT INTO finding_comments (finding_id, user_id, content)
		VALUES ($1, $2, $3)
		RETURNING id, finding_id, user_id, content, created_at, updated_at
	`, c.FindingID, c.UserID, c.Content).Scan(
		&comment.ID, &comment.FindingID, &comment.UserID, &comment.Content, &comment.CreatedAt, &comment.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("create comment: %w", err)
	}

	err = r.db.QueryRow(ctx, `SELECT username FROM users WHERE id = $1`, c.UserID).Scan(&comment.Username)
	if err != nil {
		return nil, fmt.Errorf("get username: %w", err)
	}

	return &comment, nil
}

func (r *appRepo) DeleteFindingComment(ctx context.Context, commentID int64) error {
	_, err := r.db.Exec(ctx, `DELETE FROM finding_comments WHERE id = $1`, commentID)
	return err
}
