package models

import "time"

type Repo struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	URL       string    `json:"url"`
	CreatedAt time.Time `json:"created_at"`
}

type ScanStatus = string

const (
	StatusPending   ScanStatus = "pending"
	StatusRunning   ScanStatus = "running"
	StatusCompleted ScanStatus = "completed"
	StatusFailed    ScanStatus = "failed"
)

type Scan struct {
	ID           string     `json:"id"`
	RepoID       *string    `json:"repo_id,omitempty"`
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
	ID            string        `json:"id"`
	ScanID        string        `json:"scan_id"`
	Scanner       string        `json:"scanner"`
	RuleID        string        `json:"rule_id"`
	Title         string        `json:"title"`
	Description   string        `json:"description"`
	Severity      Severity      `json:"severity"`
	FilePath      string        `json:"file_path"`
	LineStart     int           `json:"line_start"`
	LineEnd       int           `json:"line_end"`
	CodeSnippet   string        `json:"code_snippet,omitempty"`
	CreatedAt     time.Time     `json:"created_at"`
	Status        FindingStatus `json:"status"`
	AssignedTo    *string       `json:"assigned_to,omitempty"`
	FalsePositive bool          `json:"false_positive"`
	Notes         *string       `json:"notes,omitempty"`
	ResolvedAt    *time.Time    `json:"resolved_at,omitempty"`
	SLADeadline   *time.Time    `json:"sla_deadline,omitempty"`
	CVEID         *string       `json:"cve_id,omitempty"`
	CWEID         *string       `json:"cwe_id,omitempty"`
	Suppressed       bool    `json:"suppressed"`
	RemediationSlug  *string `json:"remediation_slug,omitempty"`
}

type SLASummary struct {
	Overdue    int `json:"overdue"`
	DueToday   int `json:"due_today"`
	OnTrack    int `json:"on_track"`
	NoDeadline int `json:"no_deadline"`
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
	RepoID   string `json:"repo_id"`
	RepoName string `json:"repo_name"`
	RepoURL  string `json:"repo_url"`
	Critical int    `json:"critical"`
	High     int    `json:"high"`
	Medium   int    `json:"medium"`
	Low      int    `json:"low"`
	Info     int    `json:"info"`
	Score    int    `json:"score"`
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
	Projects    []Project `json:"projects,omitempty"`
}

type Project struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	AppID       string    `json:"app_id"`
	RepoID      *string   `json:"repo_id,omitempty"`
	RepoName    *string   `json:"repo_name,omitempty"`
	RepoURL     *string   `json:"repo_url,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
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
	ID         string            `json:"id"`
	Name       string            `json:"name"`
	Conditions []PolicyCondition `json:"conditions"`
	Actions    []PolicyAction    `json:"actions"`
	Enabled    bool              `json:"enabled"`
	CreatedAt  time.Time         `json:"created_at"`
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
	Members   []User    `json:"members,omitempty"`
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

type VulnSummary struct {
	VulnID        string   `json:"vuln_id"`
	CVEID         *string  `json:"cve_id,omitempty"`
	CWEID         *string  `json:"cwe_id,omitempty"`
	Title         string   `json:"title"`
	Severity      string   `json:"severity"`
	Scanners      []string `json:"scanners"`
	AffectedCount int      `json:"affected_count"`
	FindingCount  int      `json:"finding_count"`
	OpenCount     int      `json:"open_count"`
	FixedCount    int      `json:"fixed_count"`
}

type AffectedRepo struct {
	RepoName        string   `json:"repo_name"`
	RepoURL         string   `json:"repo_url"`
	FindingCount    int      `json:"finding_count"`
	OpenCount       int      `json:"open_count"`
	FixedCount      int      `json:"fixed_count"`
	Statuses        []string `json:"statuses"`
	Assignees       []string `json:"assignees"`
	NearestDeadline *string  `json:"nearest_deadline,omitempty"`
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
