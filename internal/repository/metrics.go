package repository

import (
	"context"
	"fmt"
	"time"

	"aspm/internal/datascope"
	"aspm/internal/models"

	"github.com/jackc/pgx/v5/pgxpool"
)

type metricsRepo struct{ db *pgxpool.Pool }

func (r *metricsRepo) Summary(ctx context.Context, scope datascope.Scope) (*models.MetricsSummary, error) {
	m := &models.MetricsSummary{
		FindingsBySeverity: make(map[string]int),
		ScansByScanner:     make(map[string]int),
	}

	r.db.QueryRow(ctx, `SELECT COUNT(*) FROM scans s
		WHERE ($1::uuid IS NULL OR EXISTS (
			SELECT 1 FROM team_members tm
			JOIN apps a ON a.team_id = tm.team_id
			JOIN projects p ON p.app_id = a.id
			WHERE tm.user_id = $1 AND p.id = s.project_id
		))`, scope.UserID).Scan(&m.TotalScans)
	r.db.QueryRow(ctx, `SELECT COUNT(*) FROM scans s
		WHERE status IN ('pending','running')
		  AND ($1::uuid IS NULL OR EXISTS (
			SELECT 1 FROM team_members tm
			JOIN apps a ON a.team_id = tm.team_id
			JOIN projects p ON p.app_id = a.id
			WHERE tm.user_id = $1 AND p.id = s.project_id
		))`, scope.UserID).Scan(&m.ActiveScans)
	r.db.QueryRow(ctx, `SELECT COUNT(*) FROM findings f
		WHERE ($1::uuid IS NULL OR EXISTS (
			SELECT 1 FROM scans s2
			JOIN projects p ON s2.project_id = p.id
			JOIN apps a ON p.app_id = a.id
			JOIN team_members tm ON a.team_id = tm.team_id
			WHERE s2.id = f.scan_id AND tm.user_id = $1
		))`, scope.UserID).Scan(&m.TotalFindings)

	sevRows, _ := r.db.Query(ctx, `SELECT f.severity, COUNT(*) FROM findings f
		WHERE ($1::uuid IS NULL OR EXISTS (
			SELECT 1 FROM scans s2
			JOIN projects p ON s2.project_id = p.id
			JOIN apps a ON p.app_id = a.id
			JOIN team_members tm ON a.team_id = tm.team_id
			WHERE s2.id = f.scan_id AND tm.user_id = $1
		))
		GROUP BY f.severity`, scope.UserID)
	if sevRows != nil {
		defer sevRows.Close()
		for sevRows.Next() {
			var sev string
			var count int
			sevRows.Scan(&sev, &count)
			m.FindingsBySeverity[sev] = count
		}
	}

	scanRows, _ := r.db.Query(ctx, `SELECT s.scanner, COUNT(*) FROM scans s
		WHERE ($1::uuid IS NULL OR EXISTS (
			SELECT 1 FROM team_members tm
			JOIN apps a ON a.team_id = tm.team_id
			JOIN projects p ON p.app_id = a.id
			WHERE tm.user_id = $1 AND p.id = s.project_id
		))
		GROUP BY s.scanner`, scope.UserID)
	if scanRows != nil {
		defer scanRows.Close()
		for scanRows.Next() {
			var scanner string
			var count int
			scanRows.Scan(&scanner, &count)
			m.ScansByScanner[scanner] = count
		}
	}

	recentRows, _ := r.db.Query(ctx, `
		SELECT s.id, s.scanner, s.status, s.target, s.created_at, s.completed_at, COUNT(f.id)
		FROM scans s
		LEFT JOIN findings f ON f.scan_id = s.id
		WHERE ($1::uuid IS NULL OR EXISTS (
			SELECT 1 FROM team_members tm
			JOIN apps a ON a.team_id = tm.team_id
			JOIN projects p ON p.app_id = a.id
			WHERE tm.user_id = $1 AND p.id = s.project_id
		))
		GROUP BY s.id
		ORDER BY s.created_at DESC LIMIT 5`, scope.UserID)
	if recentRows != nil {
		defer recentRows.Close()
		for recentRows.Next() {
			var s models.Scan
			recentRows.Scan(&s.ID, &s.Scanner, &s.Status, &s.Target, &s.CreatedAt, &s.CompletedAt, &s.FindingCount)
			m.RecentScans = append(m.RecentScans, s)
		}
	}
	if m.RecentScans == nil {
		m.RecentScans = []models.Scan{}
	}

	return m, nil
}

func (r *metricsRepo) Trends(ctx context.Context, scope datascope.Scope, days int) ([]models.TrendPoint, error) {
	if days < 1 || days > 365 {
		days = 30
	}
	rows, err := r.db.Query(ctx, `
		SELECT
			DATE(f.created_at)::text AS day,
			COUNT(*) FILTER (WHERE f.severity = 'critical') AS critical,
			COUNT(*) FILTER (WHERE f.severity = 'high')     AS high,
			COUNT(*) FILTER (WHERE f.severity = 'medium')   AS medium,
			COUNT(*) FILTER (WHERE f.severity = 'low')      AS low,
			COUNT(*) FILTER (WHERE f.severity = 'info')     AS info
		FROM findings f
		WHERE f.created_at >= NOW() - make_interval(days => $2)
		  AND ($1::uuid IS NULL OR EXISTS (
			  SELECT 1 FROM scans s2
			  JOIN projects p ON s2.project_id = p.id
			  JOIN apps a ON p.app_id = a.id
			  JOIN team_members tm ON a.team_id = tm.team_id
			  WHERE s2.id = f.scan_id AND tm.user_id = $1
		  ))
		GROUP BY day
		ORDER BY day`, scope.UserID, days)
	if err != nil {
		return nil, fmt.Errorf("trends: %w", err)
	}
	defer rows.Close()

	var points []models.TrendPoint
	for rows.Next() {
		var p models.TrendPoint
		rows.Scan(&p.Date, &p.Critical, &p.High, &p.Medium, &p.Low, &p.Info)
		points = append(points, p)
	}
	if points == nil {
		points = []models.TrendPoint{}
	}
	return points, nil
}

func (r *metricsRepo) RiskScores(ctx context.Context, scope datascope.Scope) ([]models.RepoRiskScore, error) {
	rows, err := r.db.Query(ctx, `
		SELECT
			COALESCE(p.id::text, '')                           AS project_id,
			COALESCE(p.name, split_part(s.target,'/',5))       AS project_name,
			COALESCE(p.repo_url, s.target)                     AS project_url,
			COALESCE(p.app_id::text, '')                       AS app_id,
			COALESCE(a.name, '')                               AS app_name,
			COUNT(*) FILTER (WHERE f.severity = 'critical' AND f.status NOT IN ('fixed','verified','accepted_risk')) AS critical,
			COUNT(*) FILTER (WHERE f.severity = 'high'     AND f.status NOT IN ('fixed','verified','accepted_risk')) AS high,
			COUNT(*) FILTER (WHERE f.severity = 'medium'   AND f.status NOT IN ('fixed','verified','accepted_risk')) AS medium,
			COUNT(*) FILTER (WHERE f.severity = 'low'      AND f.status NOT IN ('fixed','verified','accepted_risk')) AS low,
			COUNT(*) FILTER (WHERE f.severity = 'info'     AND f.status NOT IN ('fixed','verified','accepted_risk')) AS info,
			(COUNT(*) FILTER (WHERE f.severity = 'critical' AND f.status NOT IN ('fixed','verified','accepted_risk')) * 100 +
			 COUNT(*) FILTER (WHERE f.severity = 'high'     AND f.status NOT IN ('fixed','verified','accepted_risk')) * 20  +
			 COUNT(*) FILTER (WHERE f.severity = 'medium'   AND f.status NOT IN ('fixed','verified','accepted_risk')) * 5   +
			 COUNT(*) FILTER (WHERE f.severity = 'low'      AND f.status NOT IN ('fixed','verified','accepted_risk')) * 1)  AS score
		FROM scans s
		LEFT JOIN projects p ON p.id = s.project_id OR p.repo_url = s.target
		LEFT JOIN apps a ON a.id = p.app_id
		LEFT JOIN findings f ON f.scan_id = s.id
		WHERE ($1::uuid IS NULL OR EXISTS (
			SELECT 1 FROM team_members tm
			JOIN apps a2 ON a2.team_id = tm.team_id
			JOIN projects p2 ON p2.app_id = a2.id
			WHERE tm.user_id = $1 AND p2.id = s.project_id
		))
		GROUP BY p.id, p.name, p.repo_url, p.app_id, a.name, s.target
		ORDER BY score DESC`, scope.UserID)
	if err != nil {
		return nil, fmt.Errorf("risk scores: %w", err)
	}
	defer rows.Close()

	var scores []models.RepoRiskScore
	for rows.Next() {
		var rs models.RepoRiskScore
		rows.Scan(&rs.ProjectID, &rs.ProjectName, &rs.RepoURL, &rs.AppID, &rs.AppName, &rs.Critical, &rs.High, &rs.Medium, &rs.Low, &rs.Info, &rs.Score)
		scores = append(scores, rs)
	}
	if scores == nil {
		scores = []models.RepoRiskScore{}
	}
	return scores, nil
}

func (r *metricsRepo) TeamMetrics(ctx context.Context, scope datascope.Scope) ([]models.TeamMetrics, error) {
	rows, err := r.db.Query(ctx, `
		SELECT
			t.id::text,
			t.name,
			COUNT(DISTINCT a.id)::int,
			COUNT(DISTINCT p.id)::int,
			COUNT(DISTINCT CASE WHEN p.repo_url IS NOT NULL THEN p.id END)::int,
			COALESCE(COUNT(f.id) FILTER (WHERE f.severity = 'critical' AND f.status NOT IN ('fixed','verified','accepted_risk')), 0)::int,
			COALESCE(COUNT(f.id) FILTER (WHERE f.severity = 'high'     AND f.status NOT IN ('fixed','verified','accepted_risk')), 0)::int,
			COALESCE(COUNT(f.id) FILTER (WHERE f.severity = 'medium'   AND f.status NOT IN ('fixed','verified','accepted_risk')), 0)::int,
			COALESCE(COUNT(f.id) FILTER (WHERE f.severity = 'low'      AND f.status NOT IN ('fixed','verified','accepted_risk')), 0)::int,
			COALESCE(COUNT(f.id) FILTER (WHERE f.severity = 'info'     AND f.status NOT IN ('fixed','verified','accepted_risk')), 0)::int,
			(
				COALESCE(COUNT(f.id) FILTER (WHERE f.severity = 'critical' AND f.status NOT IN ('fixed','verified','accepted_risk')), 0) * 100 +
				COALESCE(COUNT(f.id) FILTER (WHERE f.severity = 'high'     AND f.status NOT IN ('fixed','verified','accepted_risk')), 0) * 20  +
				COALESCE(COUNT(f.id) FILTER (WHERE f.severity = 'medium'   AND f.status NOT IN ('fixed','verified','accepted_risk')), 0) * 5   +
				COALESCE(COUNT(f.id) FILTER (WHERE f.severity = 'low'      AND f.status NOT IN ('fixed','verified','accepted_risk')), 0) * 1
			)::int AS score,
			ROUND(
				CASE
					WHEN COUNT(f.id) FILTER (WHERE f.sla_deadline IS NOT NULL) = 0 THEN 100.0
					ELSE 100.0
						* COUNT(f.id) FILTER (WHERE f.sla_deadline IS NOT NULL AND (f.sla_deadline >= NOW() OR f.status IN ('fixed','verified','accepted_risk')))
						/ NULLIF(COUNT(f.id) FILTER (WHERE f.sla_deadline IS NOT NULL), 0)
				END
			, 1)::float8,
			MAX(s.completed_at)
		FROM teams t
		LEFT JOIN apps a      ON a.team_id  = t.id
		LEFT JOIN projects p  ON p.app_id   = a.id OR (p.app_id IS NULL AND a.id IS NULL)
		LEFT JOIN scans s     ON s.project_id = p.id AND s.status = 'completed'
		LEFT JOIN findings f  ON f.scan_id   = s.id
		WHERE ($1::uuid IS NULL OR EXISTS (
			SELECT 1 FROM team_members tm WHERE tm.team_id = t.id AND tm.user_id = $1
		))
		GROUP BY t.id, t.name
		ORDER BY score DESC`, scope.UserID)
	if err != nil {
		return nil, fmt.Errorf("team metrics: %w", err)
	}
	defer rows.Close()

	var metrics []models.TeamMetrics
	for rows.Next() {
		var m models.TeamMetrics
		rows.Scan(
			&m.TeamID, &m.TeamName,
			&m.AppCount, &m.ProjectCount, &m.RepoCount,
			&m.Critical, &m.High, &m.Medium, &m.Low, &m.Info,
			&m.Score, &m.SLACompliance, &m.LastScanAt,
		)
		metrics = append(metrics, m)
	}
	if metrics == nil {
		metrics = []models.TeamMetrics{}
	}
	return metrics, nil
}

func (r *metricsRepo) SLACompliance(ctx context.Context, scope datascope.Scope) (*models.SLACompliance, error) {
	var s models.SLACompliance
	err := r.db.QueryRow(ctx, `
		SELECT
			COUNT(*) FILTER (WHERE sla_deadline IS NOT NULL) AS total,
			COUNT(*) FILTER (WHERE sla_deadline IS NOT NULL
			  AND (sla_deadline >= NOW() OR status IN ('fixed','verified','accepted_risk'))) AS on_time,
			COUNT(*) FILTER (WHERE sla_deadline IS NOT NULL
			  AND sla_deadline < NOW()
			  AND status NOT IN ('fixed','verified','accepted_risk')) AS overdue
		FROM findings f
		WHERE ($1::uuid IS NULL OR EXISTS (
			SELECT 1 FROM scans s2
			JOIN projects p ON s2.project_id = p.id
			JOIN apps a ON p.app_id = a.id
			JOIN team_members tm ON a.team_id = tm.team_id
			WHERE s2.id = f.scan_id AND tm.user_id = $1
		))`, scope.UserID).
		Scan(&s.Total, &s.OnTime, &s.Overdue)
	if err != nil {
		return nil, fmt.Errorf("sla compliance: %w", err)
	}
	if s.Total > 0 {
		s.Percent = float64(s.OnTime) / float64(s.Total) * 100
	}
	return &s, nil
}

// ScannerHealth returns per-scanner health metrics
func (r *metricsRepo) ScannerHealth(ctx context.Context) ([]models.ScannerHealth, error) {
	rows, err := r.db.Query(ctx, `
		SELECT
			scanner,
			COUNT(*)::int,
			COUNT(*) FILTER (WHERE status = 'completed')::int,
			COUNT(*) FILTER (WHERE status = 'failed')::int,
			COALESCE(AVG(EXTRACT(EPOCH FROM (completed_at - started_at)))
				FILTER (WHERE status = 'completed' AND started_at IS NOT NULL AND completed_at IS NOT NULL), 0)::float8,
			MAX(completed_at) FILTER (WHERE status = 'completed'),
			MAX(completed_at) FILTER (WHERE status = 'failed')
		FROM scans
		GROUP BY scanner
		ORDER BY scanner`)
	if err != nil {
		return nil, fmt.Errorf("scanner health: %w", err)
	}
	defer rows.Close()

	var results []models.ScannerHealth
	for rows.Next() {
		var s models.ScannerHealth
		if err := rows.Scan(&s.Scanner, &s.TotalScans, &s.SuccessfulScans,
			&s.FailedScans, &s.AvgDurationSeconds, &s.LastSuccessAt, &s.LastFailureAt); err != nil {
			return nil, fmt.Errorf("scanner health scan: %w", err)
		}
		if s.TotalScans > 0 {
			s.SuccessRate = float64(s.SuccessfulScans) / float64(s.TotalScans) * 100
		}
		results = append(results, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("scanner health rows: %w", err)
	}
	return results, nil
}

// PrometheusStats returns metrics for Prometheus exposition
func (r *metricsRepo) PrometheusStats(ctx context.Context) (scansTotal, scansRunning, scansFailed int, findingsBySeverity map[string]int, err error) {
	err = r.db.QueryRow(ctx, `
		SELECT
			COUNT(*) FILTER (WHERE true) AS total,
			COUNT(*) FILTER (WHERE status = 'running') AS running,
			COUNT(*) FILTER (WHERE status = 'failed') AS failed
		FROM scans`).
		Scan(&scansTotal, &scansRunning, &scansFailed)
	if err != nil {
		return 0, 0, 0, nil, fmt.Errorf("scans stats: %w", err)
	}

	rows, err := r.db.Query(ctx, `SELECT severity, COUNT(*) FROM findings GROUP BY severity`)
	if err != nil {
		return 0, 0, 0, nil, fmt.Errorf("findings stats: %w", err)
	}
	defer rows.Close()

	findingsBySeverity = make(map[string]int)
	for rows.Next() {
		var sev string
		var count int
		if err := rows.Scan(&sev, &count); err != nil {
			continue
		}
		findingsBySeverity[sev] = count
	}

	return scansTotal, scansRunning, scansFailed, findingsBySeverity, nil
}

func (r *metricsRepo) SecurityScores(ctx context.Context, scope datascope.Scope, projectID *string) ([]models.SecurityScore, error) {
	query := `
		SELECT
			p.id::text,
			p.name,
			COALESCE(COUNT(*) FILTER (WHERE f.severity = 'critical'), 0)::int,
			COALESCE(COUNT(*) FILTER (WHERE f.severity = 'high'), 0)::int,
			COALESCE(COUNT(*) FILTER (WHERE f.severity = 'medium'), 0)::int,
			COALESCE(COUNT(*) FILTER (WHERE f.severity = 'low'), 0)::int,
			MAX(s.completed_at) AS last_scan_at
		FROM projects p
		LEFT JOIN scans s ON s.project_id = p.id AND s.status = 'completed'
		LEFT JOIN findings f ON f.scan_id = s.id AND f.status NOT IN ('fixed', 'verified')
		WHERE ($1::text IS NULL OR p.id::text = $1)
		  AND ($2::uuid IS NULL OR EXISTS (
			SELECT 1 FROM team_members tm
			JOIN apps a ON a.team_id = tm.team_id
			WHERE a.id = p.app_id AND tm.user_id = $2
		  ))
		GROUP BY p.id, p.name
		ORDER BY p.name`

	rows, err := r.db.Query(ctx, query, projectID, scope.UserID)
	if err != nil {
		return nil, fmt.Errorf("security scores: %w", err)
	}
	defer rows.Close()

	var scores []models.SecurityScore
	for rows.Next() {
		var s models.SecurityScore
		if err := rows.Scan(&s.ProjectID, &s.ProjectName, &s.Critical, &s.High, &s.Medium, &s.Low, &s.LastScanAt); err != nil {
			return nil, fmt.Errorf("security scores scan: %w", err)
		}
		s.Score, s.Grade = computeSecurityGrade(s.Critical, s.High, s.Medium, s.Low, s.LastScanAt)
		scores = append(scores, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("security scores rows: %w", err)
	}
	if scores == nil {
		scores = []models.SecurityScore{}
	}
	return scores, nil
}

func computeSecurityGrade(critical, high, medium, low int, lastScanAt *time.Time) (int, string) {
	score := 100
	score -= critical * 15
	score -= high * 5
	score -= medium * 2
	score -= low * 1

	if lastScanAt == nil {
		score -= 40
	} else {
		daysSinceScan := int(time.Since(*lastScanAt).Hours() / 24)
		if daysSinceScan > 30 {
			score -= 20
		}
	}

	if score < 0 {
		score = 0
	}

	return score, mapSecurityGrade(score)
}

func mapSecurityGrade(score int) string {
	switch {
	case score >= 97:
		return "A+"
	case score >= 93:
		return "A"
	case score >= 90:
		return "A-"
	case score >= 87:
		return "B+"
	case score >= 83:
		return "B"
	case score >= 80:
		return "B-"
	case score >= 77:
		return "C+"
	case score >= 73:
		return "C"
	case score >= 70:
		return "C-"
	case score >= 67:
		return "D+"
	case score >= 63:
		return "D"
	case score >= 60:
		return "D-"
	default:
		return "F"
	}
}
