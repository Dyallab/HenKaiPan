package repository

import (
	"context"
	"time"

	"aspm/internal/models"
)

// ── Findings ──────────────────────────────────────────────────────────────────

type FindingFilter struct {
	Severities     []string
	Scanner        string
	Status         string
	Category       string
	CVESearch      string
	Overdue        bool
	ShowSuppressed bool
	Page           int
	Limit          int
	FilePath       string
	SortBy         string // "confidence_desc", "confidence_asc", "corroborated"
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
	SecretHash  string
	ProjectID   string
	Fingerprint string
}

type ExportFilter struct {
	Severities []string
	Scanner    string
	Status     string
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

type FindingSummarySource struct {
	FindingID          string
	Scanner            string
	RuleID             string
	Title              string
	Description        string
	AISummary          string
	SummaryFingerprint string
	SummaryState       string
	Severity           string
	FilePath           string
	Raw                []byte
}

type SLABreachFinding struct {
	FindingID   string
	ScanID      string
	Repository  string
	Severity    string
	Title       string
	RuleID      string
	FilePath    string
	Line        int
	Scanner     string
	SLADeadline time.Time
	CreatedAt   time.Time
}

type PreparedSummary struct {
	Fingerprint   string
	Summary       string
	State         string
	ShouldEnqueue bool
}

type FindingRepository interface {
	List(ctx context.Context, f FindingFilter) ([]models.Finding, int, error)
	GetByID(ctx context.Context, id string) (*models.Finding, error)
	GetByScanID(ctx context.Context, scanID string) ([]models.Finding, error)
	Update(ctx context.Context, id string, upd FindingUpdate) (*models.Finding, error)
	Insert(ctx context.Context, f FindingInsert) (string, error)
	RefreshBatchCorrelation(ctx context.Context, findingID string) error
	GetSLASummary(ctx context.Context) (*models.SLASummary, error)
	ExportRows(ctx context.Context, f ExportFilter) ([]models.Finding, error)
	UpdateRemediationSlug(ctx context.Context, findingID, slug string) error
	GetForRemediation(ctx context.Context, id string) (*RemediationSource, error)
	GetSummarySource(ctx context.Context, id string) (*FindingSummarySource, error)
	PrepareAISummary(ctx context.Context, findingID string) (*PreparedSummary, error)
	StoreAISummary(ctx context.Context, fingerprint, summary string) error
	MarkAISummaryFailed(ctx context.Context, fingerprint string) error
	ListPendingSLABreaches(ctx context.Context, limit int) ([]SLABreachFinding, error)
	MarkSLABreachAttempted(ctx context.Context, findingIDs []string) error
	ListUniqueFiles(ctx context.Context) ([]string, error)
}

// ── Scans ─────────────────────────────────────────────────────────────────────

type ScanRepository interface {
	List(ctx context.Context, page, limit int) ([]models.Scan, int, error)
	Get(ctx context.Context, id string) (*models.Scan, error)
	Insert(ctx context.Context, target, scanner, batchID string, projectID *string) (string, error)
	MarkRunning(ctx context.Context, scanID string) error
	MarkCompleted(ctx context.Context, scanID, containerLog string, exitErr *string) error
	MarkFailed(ctx context.Context, scanID, errMsg, containerLog string) error
	RecoverStuck(ctx context.Context) (int64, error)
}

// ── Apps + Projects ───────────────────────────────────────────────────────────

type AppUpdate struct {
	Name        *string
	Description *string
	TeamID      *string
}

type ProjectCreate struct {
	Name          string
	Description   string
	RepoURL       string
	Provider      string
	DefaultBranch string
}

type ProjectUpdate struct {
	Name           *string
	Description    *string
	RepoURL        *string
	Provider       *string
	DefaultBranch  *string
	ExternalRepoID *string
}

type AppRepository interface {
	List(ctx context.Context, teamFilter string) ([]models.App, error)
	Get(ctx context.Context, id string) (*models.App, error)
	Create(ctx context.Context, name, description string, teamID *string) (*models.App, error)
	Update(ctx context.Context, id string, upd AppUpdate) error
	Delete(ctx context.Context, id string) error
	ListProjects(ctx context.Context, appID string) ([]models.Project, error)
	ListAllProjects(ctx context.Context, appFilter string) ([]models.Project, error)
	GetProjectByID(ctx context.Context, id string) (*models.Project, error)
	CreateProject(ctx context.Context, appID string, p ProjectCreate) (*models.Project, error)
	CreateStandaloneProject(ctx context.Context, p ProjectCreate) (*models.Project, error)
	UpdateProject(ctx context.Context, id string, upd ProjectUpdate) error
	UpdateProjectGitHubToken(ctx context.Context, id, token string) error
	GetProjectGitHubToken(ctx context.Context, id string) (string, error)
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
	PrometheusStats(ctx context.Context) (scansTotal, scansRunning, scansFailed int, findingsBySeverity map[string]int, err error)
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
	Name               string
	Description        string
	Conditions         []models.PolicyCondition
	Actions            []models.PolicyAction
	PackType           string
	ComplianceControls []string
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

type AuditFilter struct {
	UserID     string
	EntityType string
	Action     string
	Page       int
	Limit      int
}

type RiskAcceptanceCreate struct {
	FindingID string
	UserID    string
	Rationale string
	ExpiresAt time.Time
	Status    string
}

type RiskAcceptanceFilter struct {
	Status    string
	FindingID string
	Page      int
	Limit     int
}

type PolicyRepository interface {
	List(ctx context.Context) ([]models.Policy, error)
	GetByID(ctx context.Context, id string) (*models.Policy, error)
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

type AuditRepository interface {
	Log(ctx context.Context, entry AuditLogEntry) error
	List(ctx context.Context, filter AuditFilter) ([]models.AuditLog, int, error)
}

type RiskAcceptanceRepository interface {
	Create(ctx context.Context, req RiskAcceptanceCreate) (*models.RiskAcceptance, error)
	GetByFindingID(ctx context.Context, findingID string) (*models.RiskAcceptance, error)
	Approve(ctx context.Context, id, approvedBy, reviewNotes string) error
	Reject(ctx context.Context, id, reviewNotes string) error
	Expire(ctx context.Context) error
	List(ctx context.Context, filter RiskAcceptanceFilter) ([]models.RiskAcceptance, int, error)
}

// ── Vulnerabilities ───────────────────────────────────────────────────────────

type VulnFilter struct {
	Severities []string
	Search     string
	OnlyOpen   bool
	Page       int
	Limit      int
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

// ── Scan Schedules ────────────────────────────────────────────────────────────

type ScanScheduleCreate struct {
	ProjectID string
	Scanner   string
	CronExpr  string
}

type ScanScheduleUpdate struct {
	Scanner  *string
	CronExpr *string
	Enabled  *bool
}

type ScheduleRepository interface {
	ListByProject(ctx context.Context, projectID string) ([]models.ScanSchedule, error)
	ListEnabled(ctx context.Context) ([]models.ScanSchedule, error)
	ListDue(ctx context.Context) ([]models.ScanSchedule, error)
	GetByID(ctx context.Context, id string) (*models.ScanSchedule, error)
	Create(ctx context.Context, s ScanScheduleCreate) (*models.ScanSchedule, error)
	Update(ctx context.Context, id string, upd ScanScheduleUpdate) (*models.ScanSchedule, error)
	Delete(ctx context.Context, id string) error
	MarkRun(ctx context.Context, id string, nextRun *time.Time) error
}

// ── Stores ────────────────────────────────────────────────────────────────────

type WebhookCreate struct {
	Label        string   `json:"label"`
	URL          string   `json:"url"`
	DeliveryType string   `json:"delivery_type"`
	Events       []string `json:"events"`
}

type WebhookUpdate struct {
	Label        *string  `json:"label"`
	URL          *string  `json:"url"`
	DeliveryType *string  `json:"delivery_type"`
	Events       []string `json:"events"`
	Enabled      *bool    `json:"enabled"`
}

type WebhookDeliveryInsert struct {
	WebhookID    string  `json:"webhook_id"`
	EventType    string  `json:"event_type"`
	Payload      []byte  `json:"payload"`
	StatusCode   *int    `json:"status_code,omitempty"`
	ResponseBody *string `json:"response_body,omitempty"`
	ErrorMessage *string `json:"error_message,omitempty"`
}

type WebhookRepository interface {
	List(ctx context.Context) ([]models.Webhook, error)
	GetByID(ctx context.Context, id string) (*models.Webhook, error)
	Create(ctx context.Context, wc WebhookCreate) (*models.Webhook, error)
	Update(ctx context.Context, id string, upd WebhookUpdate) (*models.Webhook, error)
	Delete(ctx context.Context, id string) error
	ListEnabled(ctx context.Context) ([]models.Webhook, error)
	UpdateDeliveryStats(ctx context.Context, id string, success bool, statusCode int, responseBody string, errorMsg string) error
	LogDelivery(ctx context.Context, l WebhookDeliveryInsert) error
	GetDeliveryLogs(ctx context.Context, webhookID string, limit int) ([]models.WebhookDeliveryLog, error)
}

type NotificationSettingsUpdate struct {
	AlertCritical     *bool
	AlertHigh         *bool
	AlertScanComplete *bool
	AlertScanFailed   *bool
	AlertSLABreach    *bool
	EmailRecipients   *[]string
}

type JiraIntegrationUpdate struct {
	BaseURL    *string  `json:"base_url"`
	UserEmail  *string  `json:"user_email"`
	ProjectKey *string  `json:"project_key"`
	IssueType  *string  `json:"issue_type"`
	Labels     []string `json:"labels"`
	Enabled    *bool    `json:"enabled"`
	Token      *string  `json:"token"`
}

type JiraCredentials struct {
	BaseURL    string
	UserEmail  string
	ProjectKey string
	IssueType  string
	Labels     []string
	Token      string
	Enabled    bool
}

type JiraIssueLinkUpsert struct {
	FindingID string
	IssueKey  *string
	IssueURL  *string
	Status    *string
}

type SettingsRepository interface {
	GetNotificationSettings(ctx context.Context) (*models.NotificationSettings, error)
	UpdateNotificationSettings(ctx context.Context, upd NotificationSettingsUpdate) (*models.NotificationSettings, error)
	GetJiraIntegration(ctx context.Context) (*models.JiraIntegration, error)
	GetJiraCredentials(ctx context.Context) (*JiraCredentials, error)
	UpsertJiraIntegration(ctx context.Context, upd JiraIntegrationUpdate) (*models.JiraIntegration, error)
	GetJiraIssueLinkByFindingID(ctx context.Context, findingID string) (*models.JiraIssueLink, error)
	ReserveJiraIssueLink(ctx context.Context, findingID string) (*models.JiraIssueLink, bool, error)
	UpsertJiraIssueLink(ctx context.Context, link JiraIssueLinkUpsert) (*models.JiraIssueLink, error)
	DeleteJiraIssueLink(ctx context.Context, findingID string) error
}

type Stores struct {
	Findings       FindingRepository
	Scans          ScanRepository
	Apps           AppRepository
	Schedules      ScheduleRepository
	Users          UserRepository
	Teams          TeamRepository
	Metrics        MetricsRepository
	Knowledge      KnowledgeRepository
	Policies       PolicyRepository
	Vulns          VulnerabilityRepository
	Agents         AgentRepository
	Webhooks       WebhookRepository
	Settings       SettingsRepository
	Audit          AuditRepository
	RiskAcceptance RiskAcceptanceRepository
}
