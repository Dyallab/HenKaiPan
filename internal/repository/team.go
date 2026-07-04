package repository

import (
	"context"
	"fmt"

	"aspm/internal/models"

	"github.com/jackc/pgx/v5/pgxpool"
)

type teamRepo struct{ db *pgxpool.Pool }

func (r *teamRepo) List(ctx context.Context) ([]models.Team, error) {
	rows, err := r.db.Query(ctx,
		`SELECT id, name, created_at FROM teams ORDER BY created_at`)
	if err != nil {
		return nil, fmt.Errorf("teams list: %w", err)
	}
	defer rows.Close()

	var teams []models.Team
	var ids []string
	for rows.Next() {
		var t models.Team
		if err := rows.Scan(&t.ID, &t.Name, &t.CreatedAt); err != nil {
			continue
		}
		t.Members = []models.User{}
		teams = append(teams, t)
		ids = append(ids, t.ID)
	}
	if teams == nil {
		return []models.Team{}, nil
	}

	// Batch load all members — fixes N+1
	members, err := r.membersByTeamIDs(ctx, ids)
	if err == nil {
		idx := make(map[string]int, len(teams))
		for i, t := range teams {
			idx[t.ID] = i
		}
		for teamID, users := range members {
			if i, ok := idx[teamID]; ok {
				teams[i].Members = users
			}
		}
	}

	return teams, nil
}

func (r *teamRepo) Create(ctx context.Context, name string) (*models.Team, error) {
	var t models.Team
	err := r.db.QueryRow(ctx,
		`INSERT INTO teams (name) VALUES ($1) RETURNING id, name, created_at`, name,
	).Scan(&t.ID, &t.Name, &t.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("create team: %w", err)
	}
	t.Members = []models.User{}
	return &t, nil
}

func (r *teamRepo) Delete(ctx context.Context, id string) error {
	_, err := r.db.Exec(ctx, `DELETE FROM teams WHERE id = $1`, id)
	return err
}

func (r *teamRepo) AddMember(ctx context.Context, teamID, userID string) error {
	_, err := r.db.Exec(ctx,
		`INSERT INTO team_members (team_id, user_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
		teamID, userID)
	if err != nil {
		return fmt.Errorf("add team member: %w", err)
	}
	return nil
}

func (r *teamRepo) RemoveMember(ctx context.Context, teamID, userID string) error {
	_, err := r.db.Exec(ctx,
		`DELETE FROM team_members WHERE team_id = $1 AND user_id = $2`, teamID, userID)
	return err
}

// membersByTeamIDs batch-loads members for multiple team IDs (fixes N+1).
func (r *teamRepo) membersByTeamIDs(ctx context.Context, teamIDs []string) (map[string][]models.User, error) {
	if len(teamIDs) == 0 {
		return nil, nil
	}
	rows, err := r.db.Query(ctx, `
		SELECT tm.team_id, u.id, u.username, u.email, u.role, u.created_at, u.last_login
		FROM team_members tm
		JOIN users u ON u.id = tm.user_id
		WHERE tm.team_id = ANY($1)`, teamIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make(map[string][]models.User)
	for rows.Next() {
		var teamID string
		var u models.User
		rows.Scan(&teamID, &u.ID, &u.Username, &u.Email, &u.Role, &u.CreatedAt, &u.LastLogin)
		result[teamID] = append(result[teamID], u)
	}
	return result, nil
}
