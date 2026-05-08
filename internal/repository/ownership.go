package repository

import (
	"context"
	"fmt"
)

// CheckProjectOwnership verifies if a user owns a project
// Flow: user -> team_members -> team -> apps -> project
func (r *appRepo) CheckProjectOwnership(ctx context.Context, userID, projectID string) (bool, error) {
	var count int
	err := r.db.QueryRow(ctx, `
		SELECT COUNT(*) 
		FROM projects p
		JOIN apps a ON p.app_id = a.id
		JOIN team_members tm ON a.team_id = tm.team_id
		WHERE p.id = $1 AND tm.user_id = $2
	`, projectID, userID).Scan(&count)
	
	if err != nil {
		return false, fmt.Errorf("check project ownership: %w", err)
	}
	
	return count > 0, nil
}

// CheckAppOwnership verifies if a user owns an app
// Flow: user -> team_members -> team -> app
func (r *appRepo) CheckAppOwnership(ctx context.Context, userID, appID string) (bool, error) {
	var count int
	err := r.db.QueryRow(ctx, `
		SELECT COUNT(*)
		FROM apps a
		JOIN team_members tm ON a.team_id = tm.team_id
		WHERE a.id = $1 AND tm.user_id = $2
	`, appID, userID).Scan(&count)
	
	if err != nil {
		return false, fmt.Errorf("check app ownership: %w", err)
	}
	
	return count > 0, nil
}

// CheckScanOwnership verifies if a user owns a scan
// Flow: user -> team_members -> team -> apps -> project -> scan
func (r *appRepo) CheckScanOwnership(ctx context.Context, userID, scanID string) (bool, error) {
	var count int
	err := r.db.QueryRow(ctx, `
		SELECT COUNT(*)
		FROM scans s
		JOIN projects p ON s.project_id = p.id
		JOIN apps a ON p.app_id = a.id
		JOIN team_members tm ON a.team_id = tm.team_id
		WHERE s.id = $1 AND tm.user_id = $2
	`, scanID, userID).Scan(&count)
	
	if err != nil {
		return false, fmt.Errorf("check scan ownership: %w", err)
	}
	
	return count > 0, nil
}

// CheckFindingOwnership verifies if a user owns a finding
// Flow: user -> team_members -> team -> apps -> project -> scan -> finding
func (r *appRepo) CheckFindingOwnership(ctx context.Context, userID, findingID string) (bool, error) {
	var count int
	err := r.db.QueryRow(ctx, `
		SELECT COUNT(*)
		FROM findings f
		JOIN scans s ON f.scan_id = s.id
		JOIN projects p ON s.project_id = p.id
		JOIN apps a ON p.app_id = a.id
		JOIN team_members tm ON a.team_id = tm.team_id
		WHERE f.id = $1 AND tm.user_id = $2
	`, findingID, userID).Scan(&count)
	
	if err != nil {
		return false, fmt.Errorf("check finding ownership: %w", err)
	}
	
	return count > 0, nil
}

// CheckRiskAcceptanceOwnership verifies if a user owns a risk acceptance
// Flow: user -> team_members -> team -> apps -> project -> scan -> finding -> risk_acceptance
func (r *appRepo) CheckRiskAcceptanceOwnership(ctx context.Context, userID, riskAcceptanceID string) (bool, error) {
	var count int
	err := r.db.QueryRow(ctx, `
		SELECT COUNT(*)
		FROM risk_acceptances ra
		JOIN findings f ON ra.finding_id = f.id
		JOIN scans s ON f.scan_id = s.id
		JOIN projects p ON s.project_id = p.id
		JOIN apps a ON p.app_id = a.id
		JOIN team_members tm ON a.team_id = tm.team_id
		WHERE ra.id = $1 AND tm.user_id = $2
	`, riskAcceptanceID, userID).Scan(&count)
	
	if err != nil {
		return false, fmt.Errorf("check risk acceptance ownership: %w", err)
	}
	
	return count > 0, nil
}
