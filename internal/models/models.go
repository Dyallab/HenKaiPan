package models

import "time"

type ScanStatus = string

const (
	StatusPending   ScanStatus = "pending"
	StatusRunning   ScanStatus = "running"
	StatusCompleted ScanStatus = "completed"
	StatusFailed    ScanStatus = "failed"
)

type Scan struct {
	ID           string     `json:"id"`
	ProjectID    *string    `json:"project_id,omitempty"`
	Scanner      string     `json:"scanner"`
	Status       ScanStatus `json:"status"`
	Target       string     `json:"target"`
	StartedAt    *time.Time `json:"started_at,omitempty"`
	CompletedAt  *time.Time `json:"completed_at,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	Error        *string    `json:"error,omitempty"`
	FindingCount int        `json:"finding_count"`
	ContainerLog *string    `json:"container_log,omitempty"`
}

type Severity = string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

type FindingStatus = string

const (
	FindingStatusOpen         FindingStatus = "open"
	FindingStatusInReview     FindingStatus = "in_review"
	FindingStatusAcceptedRisk FindingStatus = "accepted_risk"
	FindingStatusFixed        FindingStatus = "fixed"
	FindingStatusVerified     FindingStatus = "verified"
)

type Finding struct {
	ID                 string         `json:"id"`
	ScanID             string         `json:"scan_id"`
	Scanner            string         `json:"scanner"`
	RuleID             string         `json:"rule_id"`
	Title              string         `json:"title"`
	Description        string         `json:"description"`
	Severity           Severity       `json:"severity"`
	FilePath           string         `json:"file_path"`
	LineStart          int            `json:"line_start"`
	LineEnd            int            `json:"line_end"`
	SnippetStartLine   int            `json:"snippet_start_line,omitempty"`
	CodeSnippet        string         `json:"code_snippet,omitempty"`
	CreatedAt          time.Time      `json:"created_at"`
	Status             FindingStatus  `json:"status"`
	AssignedTo         *string        `json:"assigned_to,omitempty"`
	FalsePositive      bool           `json:"false_positive"`
	Notes              *string        `json:"notes,omitempty"`
	ResolvedAt         *time.Time     `json:"resolved_at,omitempty"`
	SLADeadline        *time.Time     `json:"sla_deadline,omitempty"`
	CVEID              *string        `json:"cve_id,omitempty"`
	CWEID              *string        `json:"cwe_id,omitempty"`
	ConfidenceScore    *float64       `json:"confidence_score,omitempty"`
	CorroborationCount int            `json:"corroboration_count"`
	AIAnalyzed         bool           `json:"ai_analyzed"`
	AISummary          string         `json:"ai_summary,omitempty"`
	SummaryState       string         `json:"summary_state,omitempty"`
	Suppressed         bool           `json:"suppressed"`
	RemediationSlug    *string        `json:"remediation_slug,omitempty"`
	JiraIssue          *JiraIssueLink `json:"jira_issue,omitempty"`
	SecretHash         string         `json:"-"`
	PkgName            string         `json:"pkg_name,omitempty"`
	PkgVersion         string         `json:"pkg_version,omitempty"`
	CorroboratingScanners string      `json:"corroborating_scanners,omitempty"`
}

type SLASummary struct {
	Overdue    int `json:"overdue"`
	DueToday   int `json:"due_today"`
	OnTrack    int `json:"on_track"`
	NoDeadline int `json:"no_deadline"`
}

type ProjectCoverage struct {
	ProjectID      string     `json:"project_id"`
	ProjectName    string     `json:"project_name"`
	LastScanAt     *time.Time `json:"last_scan_at,omitempty"`
	DaysSinceScan  *int       `json:"days_since_scan,omitempty"`
	NeverScanned   bool       `json:"never_scanned"`
}

type CoverageReport struct {
	TotalProjects     int               `json:"total_projects"`
	CoveredProjects   int               `json:"covered_projects"`
	UncoveredProjects int               `json:"uncovered_projects"`
	Projects          []ProjectCoverage `json:"projects"`
}

type MetricsSummary struct {
	TotalScans         int            `json:"total_scans"`
	ActiveScans        int            `json:"active_scans"`
	TotalFindings      int            `json:"total_findings"`
	FindingsBySeverity map[string]int `json:"findings_by_severity"`
	ScansByScanner     map[string]int `json:"scans_by_scanner"`
	RecentScans        []Scan         `json:"recent_scans"`
}

type TrendPoint struct {
	Date     string `json:"date"`
	Critical int    `json:"critical"`
	High     int    `json:"high"`
	Medium   int    `json:"medium"`
	Low      int    `json:"low"`
	Info     int    `json:"info"`
}

type RepoRiskScore struct {
	RepoID     string `json:"repo_id"`
	RepoName   string `json:"repo_name"`
	RepoURL    string `json:"repo_url"`
	ProjectID  string `json:"project_id"`
	ProjectName string `json:"project_name"`
	AppID      string `json:"app_id,omitempty"`
	AppName    string `json:"app_name,omitempty"`
	Critical   int    `json:"critical"`
	High       int    `json:"high"`
	Medium     int    `json:"medium"`
	Low        int    `json:"low"`
	Info       int    `json:"info"`
	Score      int    `json:"score"`
}

type SLACompliance struct {
	Total   int     `json:"total"`
	OnTime  int     `json:"on_time"`
	Overdue int     `json:"overdue"`
	Percent float64 `json:"percent"`
}

type App struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	TeamID      *string   `json:"team_id,omitempty"`
	TeamName    *string   `json:"team_name,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	Projects    []Project `json:"projects"`
}

type Project struct {
	ID                    string    `json:"id"`
	Name                  string    `json:"name"`
	Description           string    `json:"description,omitempty"`
	AppID                 *string   `json:"app_id,omitempty"`
	RepoURL               *string   `json:"repo_url,omitempty"`
	Provider              string    `json:"provider,omitempty"`
	DefaultBranch         string    `json:"default_branch,omitempty"`
	ExternalRepoID        *string   `json:"external_repo_id,omitempty"`
	HasToken              bool      `json:"has_token"`
	GitHubTokenExpiresAt  *time.Time `json:"github_token_expires_at,omitempty"`
	CreatedAt             time.Time `json:"created_at"`
}

type TeamMetrics struct {
	TeamID        string     `json:"team_id"`
	TeamName      string     `json:"team_name"`
	AppCount      int        `json:"app_count"`
	ProjectCount  int        `json:"project_count"`
	RepoCount     int        `json:"repo_count"`
	Critical      int        `json:"critical"`
	High          int        `json:"high"`
	Medium        int        `json:"medium"`
	Low           int        `json:"low"`
	Info          int        `json:"info"`
	Score         int        `json:"score"`
	SLACompliance float64    `json:"sla_compliance"`
	LastScanAt    *time.Time `json:"last_scan_at,omitempty"`
}

type PolicyCondition struct {
	Field string `json:"field"`
	Op    string `json:"op"`
	Value string `json:"value"`
}

type PolicyAction struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type Policy struct {
	ID                 string            `json:"id"`
	Name               string            `json:"name"`
	Description        string            `json:"description"`
	Conditions         []PolicyCondition `json:"conditions"`
	Actions            []PolicyAction    `json:"actions"`
	Enabled            bool              `json:"enabled"`
	PackType           string            `json:"pack_type"`
	ComplianceControls []string          `json:"compliance_controls"`
	CreatedAt          time.Time         `json:"created_at"`
}

type Suppression struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	RuleID      *string   `json:"rule_id,omitempty"`
	FilePattern *string   `json:"file_pattern,omitempty"`
	Scanner     *string   `json:"scanner,omitempty"`
	Reason      *string   `json:"reason,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

type User struct {
	ID        string     `json:"id"`
	Username  string     `json:"username"`
	Email     string     `json:"email"`
	Role      string     `json:"role"`
	CreatedAt time.Time  `json:"created_at"`
	LastLogin *time.Time `json:"last_login,omitempty"`
}

type Team struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
	Members   []User    `json:"members"`
}

type Article struct {
	ID            string    `json:"id"`
	Slug          string    `json:"slug"`
	Title         string    `json:"title"`
	ContentMD     string    `json:"content_md"`
	Tags          []string  `json:"tags"`
	CWEIDs        []string  `json:"cwe_ids"`
	RuleIDs       []string  `json:"rule_ids"`
	Scanner       string    `json:"scanner"`
	AutoGenerated bool      `json:"auto_generated"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

type AgentAnalysis struct {
	ID           string    `json:"id"`
	FindingID    string    `json:"finding_id"`
	AgentType    string    `json:"agent_type"`
	Confidence   float64   `json:"confidence"`
	FPLikelihood string    `json:"fp_likelihood"`
	Reasoning    string    `json:"reasoning"`
	RawOutput    []byte    `json:"raw_output,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type FindingCorrelation struct {
	ID              string    `json:"id"`
	FindingIDA      string    `json:"finding_id_a"`
	FindingIDB      string    `json:"finding_id_b"`
	CorrelationType string    `json:"correlation_type"`
	CreatedAt       time.Time `json:"created_at"`
}

type AuditLog struct {
	ID           string    `json:"id"`
	UserID       string    `json:"user_id"`
	UserEmail    string    `json:"user_email"`
	Action       string    `json:"action"`
	EntityType   string    `json:"entity_type"`
	EntityID     string    `json:"entity_id"`
	OldValue     any       `json:"old_value,omitempty"`
	NewValue     any       `json:"new_value,omitempty"`
	IPAddress    string    `json:"ip_address,omitempty"`
	UserAgent    string    `json:"user_agent,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
}

type ScanSchedule struct {
	ID           string     `json:"id"`
	ProjectID    string     `json:"project_id"`
	AppID        *string    `json:"app_id,omitempty"`
	Scanner      string     `json:"scanner"`
	ScannerType  *string    `json:"scanner_type,omitempty"`
	CronExpr     string     `json:"cron_expr"`
	Enabled      bool       `json:"enabled"`
	LastRun      *time.Time `json:"last_run,omitempty"`
	NextRun      *time.Time `json:"next_run,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
}

type RiskAcceptance struct {
	ID          string     `json:"id"`
	FindingID   string     `json:"finding_id"`
	UserID      string     `json:"user_id"`
	Rationale   string     `json:"rationale"`
	ExpiresAt   time.Time  `json:"expires_at"`
	ApprovedBy  *string    `json:"approved_by,omitempty"`
	ApprovedAt  *time.Time `json:"approved_at,omitempty"`
	Status      string     `json:"status"`
	ReviewNotes *string    `json:"review_notes,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

type EngineType = string

const (
	EngineSCA        EngineType = "sca"
	EngineSAST       EngineType = "sast"
	EngineSecrets    EngineType = "secrets"
	EngineIaC        EngineType = "iac"
	EngineContainers EngineType = "containers"
	EngineDAST       EngineType = "dast"
)

type Vulnerability struct {
	ID               string     `json:"id"`
	VulnUID          string     `json:"vuln_uid"`
	ProjectID        string     `json:"project_id"`
	Title            string     `json:"title"`
	Description      string     `json:"description,omitempty"`
	Severity         Severity   `json:"severity"`
	Status           string     `json:"status"`
	EngineType       EngineType `json:"engine_type"`
	PkgName          string     `json:"pkg_name,omitempty"`
	PkgVersion       string     `json:"pkg_version,omitempty"`
	CVEID            string     `json:"cve_id,omitempty"`
	CWEID            string     `json:"cwe_id,omitempty"`
	RuleID           string     `json:"rule_id,omitempty"`
	SecretHash       string     `json:"secret_hash,omitempty"`
	FilePath         string     `json:"file_path,omitempty"`
	FirstSeenAt      time.Time  `json:"first_seen_at"`
	LastSeenAt       time.Time  `json:"last_seen_at"`
	FindingCount     int        `json:"finding_count"`
	ScannerCoverage  []string   `json:"scanner_coverage"`
	ConfidenceScore  *float64   `json:"confidence_score,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
}

type UserNotification struct {
	ID         string    `json:"id"`
	UserID     string    `json:"user_id"`
	Title      string    `json:"title"`
	Message    string    `json:"message"`
	Type       string    `json:"type"`
	EntityType *string   `json:"entity_type,omitempty"`
	EntityID   *string   `json:"entity_id,omitempty"`
	Read       bool      `json:"read"`
	CreatedAt  time.Time `json:"created_at"`
}
