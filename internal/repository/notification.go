package repository

import (
	"context"
	"fmt"

	"aspm/internal/models"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type notificationRepo struct {
	db *pgxpool.Pool
}

func NewNotificationRepository(db *pgxpool.Pool) NotificationRepository {
	return &notificationRepo{db: db}
}

func (r *notificationRepo) Create(ctx context.Context, n NotificationCreate) (*models.UserNotification, error) {
	var notif models.UserNotification
	err := r.db.QueryRow(ctx, `
		INSERT INTO user_notifications (user_id, title, message, type, entity_type, entity_id, ai_summary)
		VALUES (@user_id, @title, @message, @type, @entity_type, @entity_id, @ai_summary)
		RETURNING id, user_id, title, message, type, entity_type, entity_id, read, ai_summary, created_at`,
		pgx.NamedArgs{
			"user_id":     n.UserID,
			"title":       n.Title,
			"message":     n.Message,
			"type":        n.Type,
			"entity_type": n.EntityType,
			"entity_id":   n.EntityID,
			"ai_summary":  n.AISummary,
		},
	).Scan(
		&notif.ID, &notif.UserID, &notif.Title, &notif.Message, &notif.Type,
		&notif.EntityType, &notif.EntityID, &notif.Read, &notif.AISummary, &notif.CreatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("create notification: %w", err)
	}
	return &notif, nil
}

func (r *notificationRepo) List(ctx context.Context, filter NotificationFilter) ([]models.UserNotification, int, error) {
	var total int
	countQuery := `SELECT COUNT(*) FROM user_notifications WHERE user_id = $1`
	countArgs := []any{filter.UserID}
	countIdx := 2

	if filter.Read != nil {
		countQuery += fmt.Sprintf(` AND read = $%d`, countIdx)
		countArgs = append(countArgs, *filter.Read)
		countIdx++
	}

	err := r.db.QueryRow(ctx, countQuery, countArgs...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count notifications: %w", err)
	}

	query := `
		SELECT id, user_id, title, message, type, entity_type, entity_id, read, ai_summary, created_at
		FROM user_notifications
		WHERE user_id = $1`
	args := []any{filter.UserID}
	argIdx := 2

	if filter.Read != nil {
		query += fmt.Sprintf(` AND read = $%d`, argIdx)
		args = append(args, *filter.Read)
		argIdx++
	}

	query += ` ORDER BY created_at DESC`
	if filter.Limit > 0 {
		query += fmt.Sprintf(` LIMIT $%d OFFSET $%d`, argIdx, argIdx+1)
		args = append(args, filter.Limit, (filter.Page-1)*filter.Limit)
	}

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list notifications: %w", err)
	}
	defer rows.Close()

	var notifications []models.UserNotification
	for rows.Next() {
		var n models.UserNotification
		err := rows.Scan(
			&n.ID, &n.UserID, &n.Title, &n.Message, &n.Type,
			&n.EntityType, &n.EntityID, &n.Read, &n.AISummary, &n.CreatedAt,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("scan notification: %w", err)
		}
		notifications = append(notifications, n)
	}
	
	if notifications == nil {
		notifications = []models.UserNotification{}
	}
	
	return notifications, total, nil
}

func (r *notificationRepo) MarkAsRead(ctx context.Context, id, userID string) error {
	result, err := r.db.Exec(ctx, `
		UPDATE user_notifications SET read = TRUE WHERE id = $1 AND user_id = $2`,
		id, userID,
	)
	if err != nil {
		return fmt.Errorf("mark as read: %w", err)
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("notification not found")
	}
	return nil
}

func (r *notificationRepo) MarkAllAsRead(ctx context.Context, userID string) error {
	_, err := r.db.Exec(ctx, `
		UPDATE user_notifications SET read = TRUE WHERE user_id = $1 AND read = FALSE`,
		userID,
	)
	if err != nil {
		return fmt.Errorf("mark all as read: %w", err)
	}
	return nil
}

func (r *notificationRepo) GetUnreadCount(ctx context.Context, userID string) (int, error) {
	var count int
	err := r.db.QueryRow(ctx, `SELECT COUNT(*) FROM user_notifications WHERE user_id = $1 AND read = FALSE`, userID).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("get unread count: %w", err)
	}
	return count, nil
}
