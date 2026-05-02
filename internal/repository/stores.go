package repository

import "github.com/jackc/pgx/v5/pgxpool"

// NewPostgresStores wires all repository implementations against a single pool.
func NewPostgresStores(db *pgxpool.Pool, redisAddr string) Stores {
	return Stores{
		Findings:       &findingRepo{db},
		Scans:          &scanRepo{db},
		Apps:           &appRepo{db},
		Users:          &userRepo{db},
		Teams:          &teamRepo{db},
		Metrics:        &metricsRepo{db},
		Knowledge:      &knowledgeRepo{db},
		Policies:       &policyRepo{db},
		Vulns:          &vulnRepo{db},
		Agents:         &agentRepo{db},
		Webhooks:       &webhookRepo{db},
		Settings:       &settingsRepo{db},
		Schedules:      &scheduleRepo{db},
		Audit:          &auditRepo{db},
		RiskAcceptance: &riskAcceptanceRepo{db},
		Health:         NewHealthRepo(db, redisAddr),
	}
}
