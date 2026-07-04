package repository

import (
	"context"
	"time"

	"aspm/internal/models"
)

// ── Findings ──────────────────────────────────────────────────────────────────

type FindingFilter struct {
	Severity       string
	Scanner        string
	Status         string
	Category       string
	CVESearch      string
	Overdue        bool
	ShowSuppressed bool
	Page           int
	Limit          int
}

type FindingUpdate struct {
	Status        *string
	AssignedTo    *string
	FalsePositive *bool
	Notes         *string
}

type FindingInsert struct {
	ScanID      string
	Scanner     string
	RuleID      string
	Title       string
	Description string
	Severity    string
	FilePath    string
	LineStart   int
	LineEnd     int
	CodeSnippet string
	Raw         []byte
	SLADeadline *time.Time
	CVEID       *string
	CWEID       *string
	Suppressed  bool
}

type ExportFilter struct {
	Severity string
	Scanner  string
	Status   string
}

type RemediationSource struct {
	RuleID      string
	Title       string
	Description string
	Severity    string
	Scanner     string
	FilePath    string
	CodeSnippet string
	CVEID       string
	CWEID       string
}

type FindingRepository interface {
	List(ctx context.Context, f FindingFilter) ([]models.Finding, int, error)
	GetByID(ctx context.Context, id string) (*models.Finding, error)
	GetByScanID(ctx context.Context, scanID string) ([]models.Finding, error)
	Update(ctx context.Context, id string, upd FindingUpdate) (*models.Finding, error)
	Insert(ctx context.Context, f FindingInsert) (string, error)
	GetSLASummary(ctx context.Context) (*models.SLASummary, error)
	ExportRows(ctx context.Context, f ExportFilter) ([]models.Finding, error)
	UpdateRemediationSlug(ctx context.Context, findingID, slug string) error
	GetForRemediation(ctx context.Context, id string) (*RemediationSource, error)
}

// ── Scans ─────────────────────────────────────────────────────────────────────

type ScanRepository interface {
	List(ctx context.Context, page, limit int) ([]models.Scan, int, error)
	Get(ctx context.Context, id string) (*models.Scan, error)
	Insert(ctx context.Context, target, scanner string, repoID *string) (string, error)
	FindRepoIDByTarget(ctx context.Context, target string) (*string, error)
	MarkRunning(ctx context.Context, scanID string) error
	MarkCompleted(ctx context.Context, scanID, containerLog string, exitErr *string) error
	MarkFailed(ctx context.Context, scanID, errMsg, containerLog string) error
	RecoverStuck(ctx context.Context) (int64, error)
}

// ── Repos ─────────────────────────────────────────────────────────────────────

type RepoRepository interface {
	List(ctx context.Context) ([]models.Repo, error)
	Create(ctx context.Context, name, url string) (*models.Repo, error)
}

// ── Apps + Projects ───────────────────────────────────────────────────────────

type AppUpdate struct {
	Name        *string
	Description *string
	TeamID      *string
}

type ProjectCreate struct {
	Name        string
	Description string
	RepoID      *string
}

type ProjectUpdate struct {
	Name        *string
	Description *string
	RepoID      *string
}

type AppRepository interface {
	List(ctx context.Context, teamFilter string) ([]models.App, error)
	Get(ctx context.Context, id string) (*models.App, error)
	Create(ctx context.Context, name, description string, teamID *string) (*models.App, error)
	Update(ctx context.Context, id string, upd AppUpdate) error
	Delete(ctx context.Context, id string) error
	ListProjects(ctx context.Context, appID string) ([]models.Project, error)
	CreateProject(ctx context.Context, appID string, p ProjectCreate) (*models.Project, error)
	UpdateProject(ctx context.Context, id string, upd ProjectUpdate) error
	DeleteProject(ctx context.Context, id string) error
}

// ── Users ─────────────────────────────────────────────────────────────────────

type UserCreate struct {
	Username     string
	Email        string
	PasswordHash string
	Role         string
}

type UserUpdate struct {
	Email        *string
	Role         *string
	PasswordHash *string
}

type UserRepository interface {
	List(ctx context.Context) ([]models.User, error)
	GetByID(ctx context.Context, id string) (*models.User, error)
	Create(ctx context.Context, u UserCreate) (*models.User, error)
	Update(ctx context.Context, id string, upd UserUpdate) (*models.User, error)
	Delete(ctx context.Context, id string) error
	GetCredentials(ctx context.Context, username string) (id, hash, role string, err error)
	UpdateLastLogin(ctx context.Context, id string) error
}

// ── Teams ─────────────────────────────────────────────────────────────────────

type TeamRepository interface {
	List(ctx context.Context) ([]models.Team, error)
	Create(ctx context.Context, name string) (*models.Team, error)
	Delete(ctx context.Context, id string) error
	AddMember(ctx context.Context, teamID, userID string) error
	RemoveMember(ctx context.Context, teamID, userID string) error
}

// ── Metrics ───────────────────────────────────────────────────────────────────

type MetricsRepository interface {
	Summary(ctx context.Context) (*models.MetricsSummary, error)
	Trends(ctx context.Context, days int) ([]models.TrendPoint, error)
	RiskScores(ctx context.Context) ([]models.RepoRiskScore, error)
	TeamMetrics(ctx context.Context) ([]models.TeamMetrics, error)
	SLACompliance(ctx context.Context) (*models.SLACompliance, error)
}

// ── Knowledge ─────────────────────────────────────────────────────────────────

type KnowledgeFilter struct {
	Search  string
	Scanner string
	Tag     string
	CWEID   string
	RuleID  string
}

type ArticleCreate struct {
	Slug          string
	Title         string
	ContentMD     string
	Tags          []string
	CWEIDs        []string
	RuleIDs       []string
	Scanner       string
	AutoGenerated bool
}

type ArticleUpdate struct {
	Title     *string
	ContentMD *string
	Tags      []string
	CWEIDs    []string
	RuleIDs   []string
	Scanner   *string
}

type KnowledgeRepository interface {
	List(ctx context.Context, f KnowledgeFilter) ([]models.Article, error)
	GetBySlug(ctx context.Context, slug string) (*models.Article, error)
	Create(ctx context.Context, a ArticleCreate) (*models.Article, error)
	Upsert(ctx context.Context, a ArticleCreate) (*models.Article, error)
	Update(ctx context.Context, slug string, upd ArticleUpdate) error
	Delete(ctx context.Context, slug string) error
	FindByRuleID(ctx context.Context, ruleID string) (*models.Article, error)
	FindByCWEOrRule(ctx context.Context, cweID, ruleID string) (*models.Article, error)
}

// ── Policies + Suppressions ───────────────────────────────────────────────────

type PolicyCreate struct {
	Name       string
	Conditions []models.PolicyCondition
	Actions    []models.PolicyAction
}

type SuppressionCreate struct {
	Name        string
	RuleID      *string
	FilePattern *string
	Scanner     *string
	Reason      *string
}

type PolicyRow struct {
	ID         string
	Conditions []models.PolicyCondition
	Actions    []models.PolicyAction
}

type PolicyRepository interface {
	List(ctx context.Context) ([]models.Policy, error)
	Create(ctx context.Context, p PolicyCreate) (*models.Policy, error)
	SetEnabled(ctx context.Context, id string, enabled bool) error
	Delete(ctx context.Context, id string) error
	ListActive(ctx context.Context) ([]PolicyRow, error)
	ExecuteActions(ctx context.Context, findingID string, actions []models.PolicyAction) error
	ListSuppressions(ctx context.Context) ([]models.Suppression, error)
	CreateSuppression(ctx context.Context, s SuppressionCreate) (*models.Suppression, error)
	DeleteSuppression(ctx context.Context, id string) error
	IsSuppressed(ctx context.Context, scanner, ruleID, filePath string) (bool, error)
}

// ── Vulnerabilities ───────────────────────────────────────────────────────────

type VulnFilter struct {
	Severity string
	Search   string
	OnlyOpen bool
	Page     int
	Limit    int
}

type VulnerabilityRepository interface {
	List(ctx context.Context, f VulnFilter) ([]models.VulnSummary, int, error)
	GetAffected(ctx context.Context, vulnID string) ([]models.AffectedRepo, error)
}

// ── Agent Analyses ────────────────────────────────────────────────────────────

type AgentAnalysisInsert struct {
	FindingID    string
	AgentType    string
	Confidence   float64
	FPLikelihood string
	Reasoning    string
	RawOutput    []byte
}

type AgentRepository interface {
	GetAnalysis(ctx context.Context, findingID, agentType string) (*models.AgentAnalysis, error)
	UpsertAnalysis(ctx context.Context, a AgentAnalysisInsert) (*models.AgentAnalysis, error)
	GetCorrelatedFindings(ctx context.Context, findingID string) ([]models.Finding, error)
	InsertCorrelations(ctx context.Context, findingID string, correlatedIDs []string, correlationType string) error
}

// ── Stores ────────────────────────────────────────────────────────────────────

type Stores struct {
	Findings  FindingRepository
	Scans     ScanRepository
	Repos     RepoRepository
	Apps      AppRepository
	Users     UserRepository
	Teams     TeamRepository
	Metrics   MetricsRepository
	Knowledge KnowledgeRepository
	Policies  PolicyRepository
	Vulns     VulnerabilityRepository
	Agents    AgentRepository
}
