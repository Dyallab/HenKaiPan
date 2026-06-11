package main

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/pprof"
	"os"
	"time"

	"aspm/internal/ai"
	"aspm/internal/auth"
	"aspm/internal/cache"
	"aspm/internal/config"
	"aspm/internal/db"
	"aspm/internal/events"
	"aspm/internal/handlers"
	"aspm/internal/license"
	"aspm/internal/logger"
	"aspm/internal/metrics"
	appmw "aspm/internal/middleware"
	"aspm/internal/ratelimit"
	"aspm/internal/queue"
	"aspm/internal/repository"
	"aspm/internal/secrets"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/hibiken/asynq"
	"github.com/rs/cors"
)

func main() {
	logger.Init()
	cfg := config.Load()

	auth.SetSecret(cfg.JWTSecret)
	secrets.SetKey(cfg.SecretEncryptionKey)
	ai.Init(cfg)
	ai.SetOpenRouterConfig(cfg.OpenRouterAPIKey, cfg.OpenRouterModel)
	if cfg.CfAPIToken != "" {
		ai.SetCloudflareConfig(cfg.CfAccountID, cfg.CfAPIToken)
	}

	pool := db.Connect(cfg.DatabaseURL)
	defer pool.Close()

	if err := db.RunMigrations(context.Background(), pool); err != nil {
		slog.Error("database migrations failed", "err", err)
		os.Exit(1)
	}

	db.EnsureAdminUser(context.Background(), pool)

	queueClient := queue.NewClient(cfg.RedisAddr)
	defer queueClient.Close()

	store := repository.NewPostgresStores(pool, cfg.RedisAddr)
	licSvc := license.New(cfg.LicenseKey)

	// Initialize rate limiter
	appmw.InitRateLimiter(cfg.RedisAddr)
	defer appmw.Close()

	// Initialize finding detail cache (reuses the rate limiter's Redis client).
	findingCache := cache.NewCache(appmw.Rdb)

	h := handlers.New(store, queueClient, cfg.FrontendURL, cfg.CookieSecure, cfg.CookieDomain, cfg.CookieSameSite, licSvc,
		cfg.RemediationConfig.IsConfigured, cfg.SummaryConfig.IsConfigured, cfg.ValidationConfig.IsConfigured,
		cfg.EmailEnabled, cfg.WebhookSecret, findingCache)

	// Per-token rate limiting constants.
	// API tokens get their own token bucket: 60 requests burst, refills at 1/sec.
	const tokenBurstCapacity = 60
	const tokenRefillPerSec  = 1.0
	tokenBucket := ratelimit.NewTokenBucket(appmw.Rdb, tokenBurstCapacity, tokenRefillPerSec)

	// Initialize Redis bridge for cross-process SSE event delivery.
	// The API process subscribes to Redis so that events published by the worker
	// reach the SSE clients connected to this API instance.
	events.InitRedisBridge(cfg.RedisAddr)
	events.SubscribeFromRedis()

	// Initialize Prometheus metrics
	redisOpt := &asynq.RedisClientOpt{Addr: cfg.RedisAddr}
	inspector := asynq.NewInspector(*redisOpt)
	defer inspector.Close()
	ctx := context.Background()

	// Start Prometheus server
	metrics.StartPrometheusServer(":9090")

	// Start queue metrics collector
	metrics.StartQueueMetricsCollector(ctx, inspector, 30*time.Second)

	// Start DB metrics collector
	getDBMetrics := func() (int, int, int, map[string]int, error) {
		// Get scan counts
		var total, running, failed int
		err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM scans`).Scan(&total)
		if err != nil {
			return 0, 0, 0, nil, err
		}
		err = pool.QueryRow(ctx, `SELECT COUNT(*) FROM scans WHERE status = 'running'`).Scan(&running)
		if err != nil {
			return 0, 0, 0, nil, err
		}
		err = pool.QueryRow(ctx, `SELECT COUNT(*) FROM scans WHERE status = 'failed'`).Scan(&failed)
		if err != nil {
			return 0, 0, 0, nil, err
		}

		// Get findings by severity
		findings := make(map[string]int)
		rows, err := pool.Query(ctx, `SELECT severity, COUNT(*) FROM findings GROUP BY severity`)
		if err != nil {
			return 0, 0, 0, nil, err
		}
		defer rows.Close()
		for rows.Next() {
			var severity string
			var count int
			if err := rows.Scan(&severity, &count); err != nil {
				continue
			}
			findings[severity] = count
		}

		return total, running, failed, findings, nil
	}
	metrics.StartDBMetricsCollector(ctx, getDBMetrics, 30*time.Second)

	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(appmw.RequestLogger)
	r.Use(appmw.RateLimiter)
	r.Use(middleware.Recoverer)
	r.Use(appmw.SecurityHeaders(cfg.CookieSecure))

	// ── Pprof profiling (EXPLICITLY ENABLED, never in production) ────
	if cfg.EnablePprof {
		slog.Warn("pprof endpoints enabled — do NOT use in production without auth")
		r.HandleFunc("/debug/pprof/", pprof.Index)
		r.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
		r.HandleFunc("/debug/pprof/profile", pprof.Profile)
		r.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
		r.HandleFunc("/debug/pprof/trace", pprof.Trace)
	}

	r.Get("/api/health", h.GetHealth)
	r.Get("/api/version", h.GetVersion)
	r.Get("/api/version/check", h.GetVersionCheck)

	r.Post("/api/auth/login", h.Login)
	r.Post("/api/auth/logout", h.Logout)

	// ── /api/v1/scans — External CI/CD endpoints (API key auth, no JWT) ────
	r.Route("/api/v1/scans", func(r chi.Router) {
		r.Use(handlers.APIKeyAuth(store, tokenBucket))
		r.Post("/external", h.CreateExternalScan)
		r.Get("/{id}/status", h.GetExternalScanStatus)
	})

	r.Route("/v1/mcp", func(r chi.Router) {
		r.Use(handlers.APIKeyAuth(store, tokenBucket))
		r.Get("/", h.HandleMCP)
		r.Post("/", h.HandleMCP)
	})

	r.Group(func(r chi.Router) {
		r.Use(auth.JWTMiddleware)

		// ── /api/v1/ — Token management (JWT auth) ──────────────────────────
		r.Route("/api/v1", func(r chi.Router) {
			r.Get("/tokens", h.ListTokens)
			r.Post("/tokens", h.CreateToken)
			r.Delete("/tokens/{id}", h.DeleteToken)
		})

		r.Get("/api/license", h.GetLicense)

		r.Get("/api/scans", h.ListScans)
		r.Post("/api/scans", h.CreateScan)
		// TODO: Restore ownership check when per-team/project visibility is implemented.
		// r.Get("/api/scans/{id}", appmw.RequireOwnership(store.Apps, "scan")(h.GetScan))
		// r.Get("/api/scans/{id}/findings", appmw.RequireOwnership(store.Apps, "scan")(h.GetScanFindings))
		r.Get("/api/scans/{id}", h.GetScan)
		r.Get("/api/scans/{id}/findings", h.GetScanFindings)

		r.Get("/api/findings", h.ListFindings)
		r.Get("/api/findings/{id}", appmw.RequireOwnership(store.Apps, "finding")(h.GetFinding))
		r.Get("/api/findings/{id}/detail", appmw.RequireOwnership(store.Apps, "finding")(h.GetFindingDetail))
		r.Patch("/api/findings/{id}", appmw.RequireOwnership(store.Apps, "finding")(h.UpdateFinding))
		r.Get("/api/findings/{id}/jira", appmw.RequireOwnership(store.Apps, "finding")(h.GetFindingJiraIssue))
		r.With(auth.RequireRole("admin")).Post("/api/findings/{id}/jira", appmw.RequireOwnership(store.Apps, "finding")(h.CreateFindingJiraIssue))
		r.Get("/api/findings/sla", h.GetSLASummary)
		r.Get("/api/findings/{id}/correlations", appmw.RequireOwnership(store.Apps, "finding")(h.GetFindingCorrelations))
		r.Post("/api/findings/{id}/summary", appmw.RequireOwnership(store.Apps, "finding")(h.RequestFindingSummary))
		r.Get("/api/findings/files", h.GetUniqueFiles)
		r.With(auth.RequireRole("admin")).Patch("/api/findings/bulk", h.BulkUpdateFindings)

		// ── SSE Events ──
		r.Get("/api/events", h.HandleSSEEvents)
		r.Get("/api/events/stats", h.GetSSEStats)

		// ── Notifications ──
		r.Get("/api/notifications", h.GetNotifications)
		r.Get("/api/notifications/unread-count", h.GetUnreadNotificationCount)
		r.Patch("/api/notifications/{id}/read", h.MarkNotificationAsRead)
		r.Patch("/api/notifications/read-all", h.MarkAllNotificationsAsRead)

		// ── Free: Vulnerability Inventory ──
		r.Get("/api/vulnerabilities", h.ListVulnerabilities)
		r.Get("/api/vulnerabilities/{vulnID}/affected", h.GetVulnerabilityAffected)
		r.Get("/api/vulnerabilities/engine-summary", h.GetVulnerabilityEngineSummary)
		r.With(auth.RequireRole("admin")).Patch("/api/vulnerabilities/{vulnID}/status", h.UpdateVulnerabilityStatus)

		// ── Paid: Comments ──
		r.With(licSvc.RequireFeature(license.FeatureComments)).Group(func(r chi.Router) {
			r.Get("/api/findings/{id}/comments", appmw.RequireOwnership(store.Apps, "finding")(h.GetFindingComments))
			r.With(auth.RequireRole("admin")).Post("/api/findings/{id}/comments", appmw.RequireOwnership(store.Apps, "finding")(h.CreateFindingComment))
			r.With(auth.RequireRole("admin")).Delete("/api/findings/{id}/comments/{commentID}", appmw.RequireOwnership(store.Apps, "finding")(h.DeleteFindingComment))
		})

		// ── Paid: Audit Log ──
		r.With(licSvc.RequireFeature(license.FeatureAuditLog)).Group(func(r chi.Router) {
			r.Get("/api/audit-logs", h.ListAuditLogs)
		})

		// ── Paid: Risk Acceptance ──
		r.With(licSvc.RequireFeature(license.FeatureRiskAcceptance)).Group(func(r chi.Router) {
			r.Get("/api/findings/{id}/risk-acceptance", appmw.RequireOwnership(store.Apps, "risk-acceptance")(http.HandlerFunc(h.GetRiskAcceptanceByFinding)))
			r.With(auth.RequireRole("admin")).Get("/api/risk-acceptances", h.ListRiskAcceptances)
			r.With(auth.RequireRole("admin")).Post("/api/risk-acceptances", h.CreateRiskAcceptance)
			r.With(auth.RequireRole("admin")).Post("/api/risk-acceptances/{id}/approve", appmw.RequireOwnership(store.Apps, "risk-acceptance")(http.HandlerFunc(h.ApproveRiskAcceptance)))
			r.With(auth.RequireRole("admin")).Post("/api/risk-acceptances/{id}/reject", appmw.RequireOwnership(store.Apps, "risk-acceptance")(http.HandlerFunc(h.RejectRiskAcceptance)))
		})

		// ── Paid: Reports & Advanced Metrics ──
		r.With(licSvc.RequireFeature(license.FeatureReports)).Group(func(r chi.Router) {
			r.Get("/api/metrics/trends", h.GetTrends)
			r.Get("/api/metrics/risk", h.GetRiskScores)
			r.Get("/api/findings/export", h.ExportFindings)
		})

		// ── Free: Core Metrics ──
		r.Get("/api/metrics/summary", h.GetMetricsSummary)
		r.Get("/api/metrics/sla-compliance", h.GetSLACompliance)
		r.Get("/api/metrics/teams", h.GetTeamMetrics)
		r.Get("/api/metrics/scanner-health", h.GetScannerHealth)

		// ── Free: Apps ──
		r.Get("/api/apps", h.ListApps)
		r.Post("/api/apps", h.CreateApp)
		r.Get("/api/apps/{id}", appmw.RequireOwnership(store.Apps, "app")(h.GetApp))
		r.Patch("/api/apps/{id}", appmw.RequireOwnership(store.Apps, "app")(h.UpdateApp))
		r.Delete("/api/apps/{id}", appmw.RequireOwnership(store.Apps, "app")(h.DeleteApp))
		r.Get("/api/apps/{id}/projects", appmw.RequireOwnership(store.Apps, "app")(h.ListProjects))
		r.Post("/api/apps/{id}/projects", appmw.RequireOwnership(store.Apps, "app")(h.CreateProject))

		// ── Free: Projects ──
		r.Get("/api/projects", h.ListProjects)
		r.Post("/api/projects", h.CreateProject)
		r.Get("/api/coverage", h.GetCoverageReport)
		r.Get("/api/projects/{projectID}", appmw.RequireOwnership(store.Apps, "project")(h.GetProject))
		r.Patch("/api/projects/{projectID}", appmw.RequireOwnership(store.Apps, "project")(h.UpdateProject))
		r.Put("/api/projects/{projectID}/github-token", appmw.RequireOwnership(store.Apps, "project")(h.UpdateProjectGitHubToken))
		r.Delete("/api/projects/{projectID}", appmw.RequireOwnership(store.Apps, "project")(h.DeleteProject))
		r.Post("/api/projects/bulk", h.BulkCreateProjects)
		r.Post("/api/projects/bulk-assign", h.BulkAssignProjects)

		// ── Paid: AI Remediation ──
		r.With(licSvc.RequireFeature(license.FeatureAIRemediation)).Group(func(r chi.Router) {
			r.Post("/api/knowledge/ai-remediate", h.AIRemediate)
			r.Post("/api/findings/{id}/analyze", appmw.RequireOwnership(store.Apps, "finding")(h.AnalyzeFinding))
			r.Get("/api/findings/{id}/analysis", appmw.RequireOwnership(store.Apps, "finding")(h.GetFindingAnalysis))
		})

		// ── Free: Knowledge (read) ──
		r.Get("/api/knowledge", h.ListArticles)
		r.Get("/api/knowledge/lookup", h.FindArticleForFinding)
		r.Get("/api/knowledge/{slug}", h.GetArticle)
		r.With(auth.RequireRole("admin")).Post("/api/knowledge", h.CreateArticle)
		r.With(auth.RequireRole("admin")).Put("/api/knowledge/{slug}", h.UpdateArticle)
		r.With(auth.RequireRole("admin")).Delete("/api/knowledge/{slug}", h.DeleteArticle)

		// ── Free: Users ──
		r.With(auth.RequireRole("admin")).Get("/api/users", h.ListUsers)
		r.With(auth.RequireRole("admin")).Post("/api/users", h.CreateUser)
		r.With(auth.RequireRole("admin")).Patch("/api/users/{id}", h.UpdateUser)
		r.With(auth.RequireRole("admin")).Delete("/api/users/{id}", h.DeleteUser)

		// ── Paid: Teams ──
		r.With(licSvc.RequireFeature(license.FeatureTeams)).Group(func(r chi.Router) {
			r.Get("/api/teams", h.ListTeams)
			r.With(auth.RequireRole("admin")).Post("/api/teams", h.CreateTeam)
			r.With(auth.RequireRole("admin")).Delete("/api/teams/{id}", h.DeleteTeam)
			r.With(auth.RequireRole("admin")).Post("/api/teams/{id}/members", h.AddTeamMember)
			r.With(auth.RequireRole("admin")).Delete("/api/teams/{id}/members/{userID}", h.RemoveTeamMember)
		})

		// ── Free: Me ──
		r.Get("/api/me", h.GetMe)

		// ── Free: Config Status ──
		r.Get("/api/config/status", h.GetConfigStatus)

		// ── Paid: Policies & Suppressions ──
		r.With(licSvc.RequireFeature(license.FeaturePolicies)).Group(func(r chi.Router) {
			r.With(auth.RequireRole("admin")).Get("/api/policies", h.ListPolicies)
			r.With(auth.RequireRole("admin")).Post("/api/policies", h.CreatePolicy)
			r.With(auth.RequireRole("admin")).Patch("/api/policies/{id}", h.UpdatePolicy)
			r.With(auth.RequireRole("admin")).Delete("/api/policies/{id}", h.DeletePolicy)

			r.With(auth.RequireRole("admin")).Get("/api/suppressions", h.ListSuppressions)
			r.With(auth.RequireRole("admin")).Post("/api/suppressions", h.CreateSuppression)
			r.With(auth.RequireRole("admin")).Delete("/api/suppressions/{id}", h.DeleteSuppression)
		})

		// ── Paid: Scheduling ──
		r.With(licSvc.RequireFeature(license.FeatureScheduling)).Group(func(r chi.Router) {
	r.Get("/api/schedules", h.ListSchedules)
	r.Get("/api/schedules/{scheduleID}", h.GetSchedule)
	r.With(auth.RequireRole("admin")).Post("/api/schedules", h.CreateSchedule)
	r.With(auth.RequireRole("admin")).Patch("/api/schedules/{scheduleID}", h.UpdateSchedule)
	r.With(auth.RequireRole("admin")).Delete("/api/schedules/{scheduleID}", h.DeleteSchedule)
		})

		// ── Free: Webhooks ──
		r.With(auth.RequireRole("admin")).Get("/api/webhooks", h.ListWebhooks)
		r.With(auth.RequireRole("admin")).Post("/api/webhooks", h.CreateWebhook)
		r.With(auth.RequireRole("admin")).Patch("/api/webhooks/{id}", h.UpdateWebhook)
		r.With(auth.RequireRole("admin")).Delete("/api/webhooks/{id}", h.DeleteWebhook)
		r.With(auth.RequireRole("admin")).Post("/api/webhooks/{id}/test", h.TestWebhook)

		// ── Paid: Email Notifications ──
		r.With(licSvc.RequireFeature(license.FeatureEmailNotify)).Group(func(r chi.Router) {
			r.With(auth.RequireRole("admin")).Get("/api/settings/notifications", h.GetNotificationSettings)
			r.With(auth.RequireRole("admin")).Patch("/api/settings/notifications", h.UpdateNotificationSettings)
			r.With(auth.RequireRole("admin")).Post("/api/settings/notifications/test-email", h.TestNotificationEmail)
		})

		// ── Paid: Integrations ──
		r.With(licSvc.RequireFeature(license.FeatureIntegrations)).Group(func(r chi.Router) {
			r.Get("/api/findings/{id}/jira", h.GetFindingJiraIssue)
			r.With(auth.RequireRole("admin")).Post("/api/findings/{id}/jira", h.CreateFindingJiraIssue)
			r.With(auth.RequireRole("admin")).Get("/api/integrations/jira", h.GetJiraIntegration)
			r.With(auth.RequireRole("admin")).Put("/api/integrations/jira", h.UpdateJiraIntegration)
		})
	})

	// Serve embedded frontend for non-API routes (production only).
	if h := frontendHandler(); h != nil {
		r.Handle("/*", h)
	}

	c := cors.New(cors.Options{
		AllowedOrigins:   cfg.AllowedOrigins,
		AllowedMethods:   []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Authorization", "Content-Type", "X-Webhook-Signature", "X-Webhook-Timestamp", "X-API-Key"},
		AllowCredentials: true,
	})

	addr := ":" + cfg.Port
	slog.Info("API listening", "addr", addr)
	if err := http.ListenAndServe(addr, c.Handler(r)); err != nil {
		slog.Error("server failed", "err", err)
		os.Exit(1)
	}
}
