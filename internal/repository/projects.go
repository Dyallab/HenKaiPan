package repository

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"aspm/internal/models"
	"aspm/internal/secrets"

	"github.com/jackc/pgx/v5"
)

func (r *appRepo) ListProjects(ctx context.Context, appID string) ([]models.Project, error) {
	rows, err := r.db.Query(ctx, `
		SELECT p.id, p.name, p.description, p.app_id, p.repo_url,
		       p.provider, p.default_branch, p.external_repo_id,
		       p.github_token_encrypted IS NOT NULL as has_token, p.created_at
		FROM projects p WHERE p.app_id = $1 ORDER BY p.name`, appID)
	if err != nil {
		return nil, fmt.Errorf("list projects: %w", err)
	}
	defer rows.Close()

	var projects []models.Project
	for rows.Next() {
		var p models.Project
		rows.Scan(&p.ID, &p.Name, &p.Description, &p.AppID, &p.RepoURL,
			&p.Provider, &p.DefaultBranch, &p.ExternalRepoID, &p.HasToken, &p.CreatedAt)
		projects = append(projects, p)
	}
	return EnsureSlice(projects), nil
}

func (r *appRepo) ListAllProjects(ctx context.Context, appFilter string) ([]models.Project, error) {
	var query string

	if appFilter == "with_app" {
		query = `
			SELECT p.id, p.name, p.description, p.app_id, p.repo_url,
			       p.provider, p.default_branch, p.external_repo_id,
			       p.github_token_encrypted IS NOT NULL as has_token, p.created_at
			FROM projects p WHERE p.app_id IS NOT NULL ORDER BY p.name`
	} else if appFilter == "without_app" {
		query = `
			SELECT p.id, p.name, p.description, p.app_id, p.repo_url,
			       p.provider, p.default_branch, p.external_repo_id,
			       p.github_token_encrypted IS NOT NULL as has_token, p.created_at
			FROM projects p WHERE p.app_id IS NULL ORDER BY p.name`
	} else {
		query = `
			SELECT p.id, p.name, p.description, p.app_id, p.repo_url,
			       p.provider, p.default_branch, p.external_repo_id,
			       p.github_token_encrypted IS NOT NULL as has_token, p.created_at
			FROM projects p ORDER BY p.name`
	}

	rows, err := r.db.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("list all projects: %w", err)
	}
	defer rows.Close()

	var projects []models.Project
	for rows.Next() {
		var p models.Project
		rows.Scan(&p.ID, &p.Name, &p.Description, &p.AppID, &p.RepoURL,
			&p.Provider, &p.DefaultBranch, &p.ExternalRepoID, &p.HasToken, &p.CreatedAt)
		projects = append(projects, p)
	}
	return EnsureSlice(projects), nil
}

// ListStandaloneByPattern returns unassigned projects whose repo_url matches the given glob pattern.
// Pattern examples:
//   - "facebook/*"       → matches https://github.com/facebook/*  
//   - "@user/*"          → matches https://github.com/user/*
//   - "org/repo-*"       → matches https://github.com/org/repo-*
//   - full URL           → exact match on repo_url
//   - plain name         → matches project name
func (r *appRepo) ListStandaloneByPattern(ctx context.Context, pattern string) ([]models.Project, error) {
	if pattern == "" {
		return r.ListAllProjects(ctx, "without_app")
	}

	// Strip @ prefix used to denote user profiles (e.g. @torvalds/* → torvalds/*)
	pattern = strings.TrimPrefix(pattern, "@")

	// Convert user-friendly pattern to SQL LIKE pattern
	var likePattern string

	if strings.HasPrefix(pattern, "https://") {
		// Full URL → convert glob chars only
		likePattern = globToLike(pattern)
	} else if strings.Contains(pattern, "/") {
		// org/repo pattern → match as https://github.com/org/repo
		likePattern = "https://github.com/" + globToLike(pattern)
	} else {
		// Plain name → match against repo_url suffix or project name
		likePattern = "%" + globToLike(pattern)
	}

	rows, err := r.db.Query(ctx, `
		SELECT p.id, p.name, p.description, p.app_id, p.repo_url,
		       p.provider, p.default_branch, p.external_repo_id,
		       p.github_token_encrypted IS NOT NULL as has_token, p.created_at
		FROM projects p
		WHERE p.app_id IS NULL
		  AND (p.repo_url ILIKE $1 OR p.name ILIKE $1)
		ORDER BY p.name`, likePattern)
	if err != nil {
		return nil, fmt.Errorf("list standalone by pattern: %w", err)
	}
	defer rows.Close()

	var projects []models.Project
	for rows.Next() {
		var p models.Project
		rows.Scan(&p.ID, &p.Name, &p.Description, &p.AppID, &p.RepoURL,
			&p.Provider, &p.DefaultBranch, &p.ExternalRepoID, &p.HasToken, &p.CreatedAt)
		projects = append(projects, p)
	}
	return EnsureSlice(projects), nil
}

// globToLike converts a glob pattern to a SQL ILIKE pattern.
// * → %, ? → _, everything else is escaped.
func globToLike(pattern string) string {
	var b strings.Builder
	for _, ch := range pattern {
		switch ch {
		case '*':
			b.WriteByte('%')
		case '?':
			b.WriteByte('_')
		case '%', '_':
			// Escape SQL wildcards that were in the original pattern
			b.WriteByte('\\')
			b.WriteRune(ch)
		default:
			b.WriteRune(ch)
		}
	}
	return b.String()
}

func (r *appRepo) GetProjectByID(ctx context.Context, id string) (*models.Project, error) {
	var p models.Project
	err := r.db.QueryRow(ctx, `
		SELECT p.id, p.name, p.description, p.app_id, p.repo_url,
		       p.provider, p.default_branch, p.external_repo_id,
		       p.github_token_encrypted IS NOT NULL as has_token, p.created_at
		FROM projects p WHERE p.id = $1`, id,
	).Scan(&p.ID, &p.Name, &p.Description, &p.AppID, &p.RepoURL,
		&p.Provider, &p.DefaultBranch, &p.ExternalRepoID, &p.HasToken, &p.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("get project: %w", err)
	}
	return &p, nil
}

func (r *appRepo) CreateProject(ctx context.Context, appID string, pc ProjectCreate) (*models.Project, error) {
	var p models.Project
	err := r.db.QueryRow(ctx, `
		INSERT INTO projects (name, description, app_id, repo_url, provider, default_branch)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id, name, description, app_id, repo_url, provider, default_branch, external_repo_id, created_at`,
		pc.Name, pc.Description, nilOrUUID(appID), pc.RepoURL, pc.Provider, pc.DefaultBranch,
	).Scan(&p.ID, &p.Name, &p.Description, &p.AppID, &p.RepoURL,
		&p.Provider, &p.DefaultBranch, &p.ExternalRepoID, &p.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("create project: %w", err)
	}
	return &p, nil
}

func (r *appRepo) CreateStandaloneProject(ctx context.Context, pc ProjectCreate) (*models.Project, error) {
	var p models.Project
	err := r.db.QueryRow(ctx, `
		INSERT INTO projects (name, description, repo_url, provider, default_branch)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, name, description, app_id, repo_url, provider, default_branch, external_repo_id, created_at`,
		pc.Name, pc.Description, pc.RepoURL, pc.Provider, pc.DefaultBranch,
	).Scan(&p.ID, &p.Name, &p.Description, &p.AppID, &p.RepoURL,
		&p.Provider, &p.DefaultBranch, &p.ExternalRepoID, &p.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("create standalone project: %w", err)
	}
	return &p, nil
}

func (r *appRepo) BulkCreateProjects(ctx context.Context, appID string, projects []ProjectCreate) ([]BulkCreateResult, error) {
	if len(projects) == 0 {
		return nil, nil
	}

	paramsPerRow := 5
	colNames := "name, description, repo_url, provider, default_branch"
	var conflictTarget string

	if appID != "" {
		paramsPerRow = 6
		colNames = "name, description, repo_url, provider, default_branch, app_id"
		conflictTarget = "ON CONFLICT (app_id, name) WHERE app_id IS NOT NULL DO NOTHING"
	} else {
		conflictTarget = "ON CONFLICT (name) WHERE app_id IS NULL DO NOTHING"
	}

	var valueStrings []string
	var args []interface{}
	for i, p := range projects {
		base := i * paramsPerRow
		if appID != "" {
			valueStrings = append(valueStrings, fmt.Sprintf("($%d,$%d,$%d,$%d,$%d,$%d)", base+1, base+2, base+3, base+4, base+5, base+6))
			args = append(args, p.Name, p.Description, p.RepoURL, p.Provider, p.DefaultBranch, nilOrUUID(appID))
		} else {
			valueStrings = append(valueStrings, fmt.Sprintf("($%d,$%d,$%d,$%d,$%d)", base+1, base+2, base+3, base+4, base+5))
			args = append(args, p.Name, p.Description, p.RepoURL, p.Provider, p.DefaultBranch)
		}
	}

	query := fmt.Sprintf(
		"INSERT INTO projects (%s) VALUES %s %s RETURNING id, name, repo_url",
		colNames, strings.Join(valueStrings, ","), conflictTarget,
	)

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("bulk create projects: %w", err)
	}
	defer rows.Close()

	created := make(map[string]string, len(projects))
	for rows.Next() {
		var id, name, repoURL string
		if err := rows.Scan(&id, &name, &repoURL); err != nil {
			return nil, fmt.Errorf("scan bulk result: %w", err)
		}
		created[name] = id
	}

	results := make([]BulkCreateResult, len(projects))
	for i, p := range projects {
		if id, ok := created[p.Name]; ok {
			results[i] = BulkCreateResult{Name: p.Name, RepoURL: p.RepoURL, ProjectID: id, Created: true}
		} else {
			results[i] = BulkCreateResult{Name: p.Name, RepoURL: p.RepoURL, Created: false}
		}
	}
	return results, nil
}

func (r *appRepo) UpdateProject(ctx context.Context, id string, upd ProjectUpdate) error {
	_, err := r.db.Exec(ctx, `
		UPDATE projects SET
			name            = COALESCE($2, name),
			description     = COALESCE($3, description),
			repo_url        = COALESCE($4, repo_url),
			provider        = COALESCE($5, provider),
			default_branch  = COALESCE($6, default_branch),
			external_repo_id = COALESCE($7, external_repo_id),
			app_id          = CASE
			                  WHEN $8::text IS NULL THEN app_id
			                  WHEN $8::text = '' THEN NULL
			                  ELSE $8::uuid
			                END,
			updated_at      = NOW()
		WHERE id = $1`, id, upd.Name, upd.Description, upd.RepoURL, upd.Provider, upd.DefaultBranch, upd.ExternalRepoID, upd.AppID)
	return err
}

func (r *appRepo) AssignProjectsToApp(ctx context.Context, appID string, projectIDs []string) (int64, error) {
	if len(projectIDs) == 0 {
		return 0, nil
	}
	res, err := r.db.Exec(ctx, `
		UPDATE projects SET app_id = $1, updated_at = NOW()
		WHERE id::text = ANY($2) AND app_id IS NULL`,
		nilOrUUID(appID), projectIDs)
	if err != nil {
		return 0, fmt.Errorf("assign projects to app: %w", err)
	}
	return res.RowsAffected(), nil
}

func (r *appRepo) UpdateProjectGitHubToken(ctx context.Context, id, token string, expiresAt *time.Time) error {
	if token == "" {
		_, err := r.db.Exec(ctx, `UPDATE projects SET github_token_encrypted = NULL, github_token_expires_at = NULL WHERE id = $1`, id)
		return err
	}

	encrypted, err := secrets.Encrypt(token)
	if err != nil {
		return fmt.Errorf("encrypt token: %w", err)
	}

	_, err = r.db.Exec(ctx, `UPDATE projects SET github_token_encrypted = $1, github_token_expires_at = $2 WHERE id = $3`, []byte(encrypted), expiresAt, id)
	return err
}

func (r *appRepo) GetProjectGitHubToken(ctx context.Context, id string) (string, error) {
	var token []byte
	err := r.db.QueryRow(ctx, `SELECT github_token_encrypted FROM projects WHERE id = $1`, id).Scan(&token)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", nil
		}
		return "", fmt.Errorf("get token: %w", err)
	}
	if token == nil || len(token) == 0 {
		return "", nil
	}

	decrypted, err := secrets.Decrypt(string(token))
	if err != nil {
		return "", fmt.Errorf("decrypt token: %w", err)
	}
	return decrypted, nil
}

func (r *appRepo) GetCoverageReport(ctx context.Context, days int) (*models.CoverageReport, error) {
	query := `
		WITH project_last_scan AS (
			SELECT 
				p.id as project_id,
				p.name as project_name,
				MAX(s.created_at) as last_scan_at
			FROM projects p
			LEFT JOIN scans s ON s.project_id = p.id AND s.status = 'completed'
			GROUP BY p.id, p.name
		)
		SELECT 
			project_id,
			project_name,
			last_scan_at,
			CASE 
				WHEN last_scan_at IS NULL THEN NULL
				ELSE EXTRACT(DAY FROM (NOW() - last_scan_at))::int
			END as days_since_scan,
			CASE WHEN last_scan_at IS NULL THEN true ELSE false END as never_scanned
		FROM project_last_scan
		ORDER BY 
			CASE WHEN last_scan_at IS NULL THEN 0 ELSE 1 END,
			last_scan_at ASC
	`

	if days > 0 {
		query = `
			WITH project_last_scan AS (
				SELECT 
					p.id as project_id,
					p.name as project_name,
					MAX(s.created_at) as last_scan_at
				FROM projects p
				LEFT JOIN scans s ON s.project_id = p.id AND s.status = 'completed'
				GROUP BY p.id, p.name
			)
			SELECT 
				project_id,
				project_name,
				last_scan_at,
				CASE 
					WHEN last_scan_at IS NULL THEN NULL
					ELSE EXTRACT(DAY FROM (NOW() - last_scan_at))::int
				END as days_since_scan,
				CASE WHEN last_scan_at IS NULL THEN true ELSE false END as never_scanned
			FROM project_last_scan
			WHERE last_scan_at IS NULL OR last_scan_at < NOW() - ($1 || ' days')::interval
			ORDER BY 
				CASE WHEN last_scan_at IS NULL THEN 0 ELSE 1 END,
				last_scan_at ASC
		`
	}

	var rows interface {
		Next() bool
		Scan(dest ...interface{}) error
		Close()
	}
	var err error

	if days > 0 {
		rows, err = r.db.Query(ctx, query, days)
	} else {
		rows, err = r.db.Query(ctx, query)
	}
	if err != nil {
		return nil, fmt.Errorf("get coverage report: %w", err)
	}
	defer rows.Close()

	var projects []models.ProjectCoverage
	var totalProjects int
	for rows.Next() {
		var pc models.ProjectCoverage
		err := rows.Scan(&pc.ProjectID, &pc.ProjectName, &pc.LastScanAt, &pc.DaysSinceScan, &pc.NeverScanned)
		if err != nil {
			return nil, fmt.Errorf("scan coverage row: %w", err)
		}
		projects = append(projects, pc)
		totalProjects++
	}

	coveredProjects := 0
	uncoveredProjects := 0
	for _, p := range projects {
		if p.NeverScanned {
			uncoveredProjects++
		} else {
			coveredProjects++
		}
	}

	return &models.CoverageReport{
		TotalProjects:     totalProjects,
		CoveredProjects:   coveredProjects,
		UncoveredProjects: uncoveredProjects,
		Projects:          projects,
	}, nil
}

func (r *appRepo) DeleteProject(ctx context.Context, id string) error {
	return DeleteByID(ctx, r.db, "projects", id)
}

// projectsByAppIDs batch-loads projects for multiple app IDs (fixes N+1).
func (r *appRepo) projectsByAppIDs(ctx context.Context, appIDs []string) ([]models.Project, error) {
	if len(appIDs) == 0 {
		return nil, nil
	}
	rows, err := r.db.Query(ctx, `
		SELECT p.id, p.name, p.description, p.app_id, p.repo_url,
		       p.provider, p.default_branch, p.external_repo_id,
		       p.github_token_encrypted IS NOT NULL as has_token, p.created_at
		FROM projects p
		WHERE p.app_id = ANY($1)
		ORDER BY p.app_id, p.name`,
		appIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var projects []models.Project
	for rows.Next() {
		var p models.Project
		rows.Scan(&p.ID, &p.Name, &p.Description, &p.AppID, &p.RepoURL,
			&p.Provider, &p.DefaultBranch, &p.ExternalRepoID, &p.HasToken, &p.CreatedAt)
		projects = append(projects, p)
	}
	return projects, nil
}

func nilOrUUID(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
