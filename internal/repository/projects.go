package repository

import (
	"context"
	"fmt"

	"aspm/internal/models"
	"aspm/internal/secrets"
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

func (r *appRepo) UpdateProject(ctx context.Context, id string, upd ProjectUpdate) error {
	_, err := r.db.Exec(ctx, `
		UPDATE projects SET
			name            = COALESCE($2, name),
			description     = COALESCE($3, description),
			repo_url        = COALESCE($4, repo_url),
			provider        = COALESCE($5, provider),
			default_branch  = COALESCE($6, default_branch),
			external_repo_id = COALESCE($7, external_repo_id),
			updated_at      = NOW()
		WHERE id = $1`, id, upd.Name, upd.Description, upd.RepoURL, upd.Provider, upd.DefaultBranch, upd.ExternalRepoID)
	return err
}

func (r *appRepo) UpdateProjectGitHubToken(ctx context.Context, id, token string) error {
	if token == "" {
		_, err := r.db.Exec(ctx, `UPDATE projects SET github_token_encrypted = NULL WHERE id = $1`, id)
		return err
	}

	encrypted, err := secrets.Encrypt(token)
	if err != nil {
		return fmt.Errorf("encrypt token: %w", err)
	}

	_, err = r.db.Exec(ctx, `UPDATE projects SET github_token_encrypted = $1 WHERE id = $2`, encrypted, id)
	return err
}

func (r *appRepo) GetProjectGitHubToken(ctx context.Context, id string) (string, error) {
	var token *string
	err := r.db.QueryRow(ctx, `SELECT github_token_encrypted FROM projects WHERE id = $1`, id).Scan(&token)
	if err != nil {
		return "", fmt.Errorf("get token: %w", err)
	}
	if token == nil || *token == "" {
		return "", nil
	}

	decrypted, err := secrets.Decrypt(*token)
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
