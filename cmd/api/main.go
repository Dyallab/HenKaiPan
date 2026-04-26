package main

import (
	"log/slog"
	"net/http"
	"os"

	"aspm/internal/ai"
	"aspm/internal/auth"
	"aspm/internal/config"
	"aspm/internal/db"
	"aspm/internal/handlers"
	"aspm/internal/logger"
	appmw "aspm/internal/middleware"
	"aspm/internal/queue"
	"aspm/internal/repository"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/rs/cors"
)

func main() {
	logger.Init()
	cfg := config.Load()

	auth.SetSecret(cfg.JWTSecret)
	ai.Init(cfg)
	ai.SetOpenRouterConfig(cfg.OpenRouterAPIKey, cfg.OpenRouterModel)
	if cfg.CfAPIToken != "" {
		ai.SetCloudflareConfig(cfg.CfAccountID, cfg.CfAPIToken)
	}

	pool := db.Connect(cfg.DatabaseURL)
	defer pool.Close()

	queueClient := queue.NewClient(cfg.RedisAddr)
	defer queueClient.Close()

	store := repository.NewPostgresStores(pool)
	h := handlers.New(store, queueClient, cfg.FrontendURL)

	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(appmw.RequestLogger)
	r.Use(middleware.Recoverer)

	r.Post("/api/auth/login", h.Login)

	r.Group(func(r chi.Router) {
		r.Use(auth.JWTMiddleware)

		r.Get("/api/scans", h.ListScans)
		r.Post("/api/scans", h.CreateScan)
		r.Get("/api/scans/{id}", h.GetScan)
		r.Get("/api/scans/{id}/findings", h.GetScanFindings)

		r.Get("/api/findings", h.ListFindings)
		r.Get("/api/findings/{id}", h.GetFinding)
		r.Patch("/api/findings/{id}", h.UpdateFinding)
		r.Get("/api/findings/{id}/jira", h.GetFindingJiraIssue)
		r.With(auth.RequireRole("admin", "analyst")).Post("/api/findings/{id}/jira", h.CreateFindingJiraIssue)
		r.Get("/api/findings/sla", h.GetSLASummary)
		r.Get("/api/findings/{id}/correlations", h.GetFindingCorrelations)
		r.Get("/api/findings/{id}/analysis", h.GetFindingAnalysis)
		r.Post("/api/findings/{id}/analyze", h.AnalyzeFinding)
		r.Get("/api/findings/files", h.GetUniqueFiles)

		r.Get("/api/repos", h.ListRepos)
		r.Post("/api/repos", h.CreateRepo)
		r.With(auth.RequireRole("admin")).Delete("/api/repos/{id}", h.DeleteRepo)

		r.Get("/api/metrics/summary", h.GetMetricsSummary)
		r.Get("/api/metrics/trends", h.GetTrends)
		r.Get("/api/metrics/risk", h.GetRiskScores)
		r.Get("/api/metrics/sla-compliance", h.GetSLACompliance)
		r.Get("/api/metrics/teams", h.GetTeamMetrics)

		r.Get("/api/apps", h.ListApps)
		r.Post("/api/apps", h.CreateApp)
		r.Get("/api/apps/{id}", h.GetApp)
		r.Patch("/api/apps/{id}", h.UpdateApp)
		r.Delete("/api/apps/{id}", h.DeleteApp)
		r.Get("/api/apps/{id}/projects", h.ListProjects)
		r.Post("/api/apps/{id}/projects", h.CreateProject)
		r.Patch("/api/apps/{id}/projects/{projectID}", h.UpdateProject)
		r.Delete("/api/apps/{id}/projects/{projectID}", h.DeleteProject)

		r.Get("/api/findings/export", h.ExportFindings)

		r.Get("/api/scanners", h.ListScanners)

		r.Get("/api/vulnerabilities", h.ListVulnerabilities)
		r.Get("/api/vulnerabilities/{vulnID}/affected", h.GetVulnerabilityAffected)

		r.Get("/api/knowledge", h.ListArticles)
		r.Get("/api/knowledge/lookup", h.FindArticleForFinding)
		r.Get("/api/knowledge/{slug}", h.GetArticle)
		r.Post("/api/knowledge/ai-remediate", h.AIRemediate)
		r.With(auth.RequireRole("admin")).Post("/api/knowledge", h.CreateArticle)
		r.With(auth.RequireRole("admin")).Put("/api/knowledge/{slug}", h.UpdateArticle)
		r.With(auth.RequireRole("admin")).Delete("/api/knowledge/{slug}", h.DeleteArticle)

		r.With(auth.RequireRole("admin")).Get("/api/users", h.ListUsers)
		r.With(auth.RequireRole("admin")).Post("/api/users", h.CreateUser)
		r.With(auth.RequireRole("admin")).Patch("/api/users/{id}", h.UpdateUser)
		r.With(auth.RequireRole("admin")).Delete("/api/users/{id}", h.DeleteUser)

		r.Get("/api/teams", h.ListTeams)
		r.With(auth.RequireRole("admin")).Post("/api/teams", h.CreateTeam)
		r.With(auth.RequireRole("admin")).Delete("/api/teams/{id}", h.DeleteTeam)
		r.With(auth.RequireRole("admin")).Post("/api/teams/{id}/members", h.AddTeamMember)
		r.With(auth.RequireRole("admin")).Delete("/api/teams/{id}/members/{userID}", h.RemoveTeamMember)

		r.Get("/api/me", h.GetMe)

		r.With(auth.RequireRole("admin")).Get("/api/policies", h.ListPolicies)
		r.With(auth.RequireRole("admin")).Post("/api/policies", h.CreatePolicy)
		r.With(auth.RequireRole("admin")).Patch("/api/policies/{id}", h.UpdatePolicy)
		r.With(auth.RequireRole("admin")).Delete("/api/policies/{id}", h.DeletePolicy)

		r.With(auth.RequireRole("admin")).Get("/api/suppressions", h.ListSuppressions)
		r.With(auth.RequireRole("admin")).Post("/api/suppressions", h.CreateSuppression)
		r.With(auth.RequireRole("admin")).Delete("/api/suppressions/{id}", h.DeleteSuppression)

		r.With(auth.RequireRole("admin")).Get("/api/webhooks", h.ListWebhooks)
		r.With(auth.RequireRole("admin")).Post("/api/webhooks", h.CreateWebhook)
		r.With(auth.RequireRole("admin")).Patch("/api/webhooks/{id}", h.UpdateWebhook)
		r.With(auth.RequireRole("admin")).Delete("/api/webhooks/{id}", h.DeleteWebhook)
		r.With(auth.RequireRole("admin")).Post("/api/webhooks/{id}/test", h.TestWebhook)
		r.With(auth.RequireRole("admin")).Get("/api/settings/notifications", h.GetNotificationSettings)
		r.With(auth.RequireRole("admin")).Patch("/api/settings/notifications", h.UpdateNotificationSettings)
		r.With(auth.RequireRole("admin")).Get("/api/integrations/jira", h.GetJiraIntegration)
		r.With(auth.RequireRole("admin")).Put("/api/integrations/jira", h.UpdateJiraIntegration)
	})

	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"http://localhost:4321", "http://localhost:4322", "http://localhost:3000"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Authorization", "Content-Type"},
		AllowCredentials: true,
	})

	addr := ":" + cfg.Port
	slog.Info("API listening", "addr", addr)
	if err := http.ListenAndServe(addr, c.Handler(r)); err != nil {
		slog.Error("server failed", "err", err)
		os.Exit(1)
	}
}
