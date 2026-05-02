export const API_BASE = "http://localhost:8080";

interface SuppressionCreate {
  Name: string;
  RuleID: string;
  FilePattern: string;
  Scanner: string;
  Reason: string;
}

function serializeMultiValue(value: string | string[]): string {
  return Array.isArray(value) ? value.join(",") : value;
}

async function req<T>(path: string, options?: RequestInit): Promise<T> {
  try {
    const res = await fetch(`${API_BASE}${path}`, {
      ...options,
      credentials: "include",
      headers: {
        "Content-Type": "application/json",
        ...(options?.headers ?? {}),
      },
    });
    if (res.status === 401) {
      console.warn("Unauthorized, redirecting to login");
      window.location.href = "/login";
      throw new Error("unauthorized");
    }
    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: res.statusText }));
      const errorMsg = err.error ?? res.statusText;
      console.error(`API Error [${res.status}]:`, errorMsg, "Path:", path);
      throw new Error(errorMsg);
    }
    if (res.status === 204) {
      return undefined as T;
    }

    const text = await res.text();
    if (!text) {
      return undefined as T;
    }

    return JSON.parse(text) as T;
  } catch (error) {
    // Re-throw to let calling code handle it
    throw error;
  }
}

export const api = {
  login: (username: string, password: string) =>
    req<{ role: string; username: string }>("/api/auth/login", {
      method: "POST",
      body: JSON.stringify({ username, password }),
    }),

  logout: () => req<void>("/api/auth/logout", { method: "POST" }),

  getMetrics: () => req<MetricsSummary>("/api/metrics/summary"),

  getScans: (page = 1, limit = 20) =>
    req<{ scans: Scan[]; total: number }>(
      `/api/scans?page=${page}&limit=${limit}`,
    ),

  createScan: (target: string, scanner: string, project_id?: string) =>
    req<{ ids: string[] }>("/api/scans", {
      method: "POST",
      body: JSON.stringify({ target, scanner, project_id }),
    }),

  getScan: (id: string) => req<Scan>(`/api/scans/${id}`),

  getScanFindings: (id: string) => req<Finding[]>(`/api/scans/${id}/findings`),

  getFindings: (
    severity: string | string[] = "",
    scanner = "",
    page = 1,
    limit = 50,
    status = "",
    overdue = false,
    category = "",
    cve_id = "",
    suppressed = false,
    file_path = "",
  ) =>
    req<{ findings: Finding[]; total: number }>(
      `/api/findings?severity=${encodeURIComponent(serializeMultiValue(severity))}&scanner=${scanner}&page=${page}&limit=${limit}&status=${status}&overdue=${overdue}&category=${category}&cve_id=${encodeURIComponent(cve_id)}&suppressed=${suppressed}&file_path=${encodeURIComponent(file_path)}`,
    ),

  getUniqueFiles: () => req<string[]>(`/api/findings/files`),

  getFinding: (id: string) => req<Finding>(`/api/findings/${id}`),

  getFindingCorrelations: (id: string) =>
    req<{ findings: Finding[]; total: number }>(
      `/api/findings/${id}/correlations`,
    ),

  getFindingAnalysis: (id: string) =>
    req<AgentAnalysis>(`/api/findings/${id}/analysis`),

  analyzeFinding: (id: string) =>
    req<{ status: string; finding_id: string }>(`/api/findings/${id}/analyze`, {
      method: "POST",
    }),

  updateFinding: (
    id: string,
    updates: {
      status?: string;
      assigned_to?: string;
      false_positive?: boolean;
      notes?: string;
    },
  ) =>
    req<Finding>(`/api/findings/${id}`, {
      method: "PATCH",
      body: JSON.stringify(updates),
    }),

  getSLASummary: () => req<SLASummary>("/api/findings/sla"),

  getTrends: (days = 30) =>
    req<TrendPoint[]>(`/api/metrics/trends?days=${days}`),
  getRiskScores: () => req<RepoRiskScore[]>("/api/metrics/risk"),
  getSLACompliance: () => req<SLACompliance>("/api/metrics/sla-compliance"),

  exportFindingsURL: (
    severity: string | string[] = "",
    scanner = "",
    status = "",
  ) =>
    `http://localhost:8080/api/findings/export?severity=${encodeURIComponent(serializeMultiValue(severity))}&scanner=${scanner}&status=${status}`,

  getMe: () => req<User>("/api/me"),

  // Knowledge Center
  getArticles: (q = "", scanner = "", tag = "", cwe_id = "", rule_id = "") =>
    req<Article[]>(
      `/api/knowledge?q=${encodeURIComponent(q)}&scanner=${scanner}&tag=${encodeURIComponent(tag)}&cwe_id=${encodeURIComponent(cwe_id)}&rule_id=${encodeURIComponent(rule_id)}`,
    ),

  getArticle: (slug: string) => req<Article>(`/api/knowledge/${slug}`),

  lookupArticle: (rule_id: string, cwe_id: string) =>
    req<{ found: boolean; article?: Article }>(
      `/api/knowledge/lookup?rule_id=${encodeURIComponent(rule_id)}&cwe_id=${encodeURIComponent(cwe_id)}`,
    ),

  aiRemediate: (finding_id: string) =>
    req<{ article: Article; cached: boolean }>("/api/knowledge/ai-remediate", {
      method: "POST",
      body: JSON.stringify({ finding_id }),
    }),

  createArticle: (data: {
    title: string;
    content_md: string;
    tags: string[];
    cwe_ids: string[];
    rule_ids: string[];
    scanner: string;
  }) =>
    req<Article>("/api/knowledge", {
      method: "POST",
      body: JSON.stringify(data),
    }),

  updateArticle: (
    slug: string,
    data: Partial<{
      title: string;
      content_md: string;
      tags: string[];
      cwe_ids: string[];
      rule_ids: string[];
      scanner: string;
    }>,
  ) =>
    req<Article>(`/api/knowledge/${slug}`, {
      method: "PUT",
      body: JSON.stringify(data),
    }),

  deleteArticle: (slug: string) =>
    req<void>(`/api/knowledge/${slug}`, { method: "DELETE" }),

  getVulnerabilities: (
    severity: string | string[] = "",
    q = "",
    open = true,
    page = 1,
    limit = 100,
  ) =>
    req<{ vulnerabilities: VulnSummary[]; total: number }>(
      `/api/vulnerabilities?severity=${encodeURIComponent(serializeMultiValue(severity))}&q=${encodeURIComponent(q)}&open=${open}&page=${page}&limit=${limit}`,
    ),

  getVulnerabilityAffected: (vulnID: string) =>
    req<AffectedRepo[]>(
      `/api/vulnerabilities/${encodeURIComponent(vulnID)}/affected`,
    ),

  getUsers: () => req<User[]>("/api/users"),

  createUser: (
    username: string,
    email: string,
    password: string,
    role: string,
  ) =>
    req<User>("/api/users", {
      method: "POST",
      body: JSON.stringify({ username, email, password, role }),
    }),

  updateUser: (
    id: string,
    updates: { email?: string; role?: string; password?: string },
  ) =>
    req<User>(`/api/users/${id}`, {
      method: "PATCH",
      body: JSON.stringify(updates),
    }),

  deleteUser: (id: string) =>
    req<void>(`/api/users/${id}`, { method: "DELETE" }),

  getTeamMetrics: () => req<TeamMetrics[]>("/api/metrics/teams"),

  getApps: (teamId = "") =>
    req<App[]>(`/api/apps${teamId ? `?team_id=${teamId}` : ""}`),

  createApp: (name: string, description: string, teamId: string | null) =>
    req<App>("/api/apps", {
      method: "POST",
      body: JSON.stringify({ name, description, team_id: teamId }),
    }),

  updateApp: (
    id: string,
    updates: { name?: string; description?: string; team_id?: string },
  ) =>
    req<void>(`/api/apps/${id}`, {
      method: "PATCH",
      body: JSON.stringify(updates),
    }),

  deleteApp: (id: string) => req<void>(`/api/apps/${id}`, { method: "DELETE" }),

  getProjects: (filter = "") =>
    req<Project[]>(`/api/projects${filter ? `?filter=${filter}` : ""}`),

  getAppProjects: (appId: string) =>
    req<Project[]>(`/api/apps/${appId}/projects`),

  createProject: (
    data: {
      name: string;
      description?: string;
      app_id?: string | null;
      repo_url?: string;
      provider?: string;
      default_branch?: string;
    },
  ) =>
    req<Project>("/api/projects", {
      method: "POST",
      body: JSON.stringify(data),
    }),

  getProject: (id: string) => req<Project>(`/api/projects/${id}`),

  updateProject: (
    id: string,
    updates: {
      name?: string;
      description?: string;
      repo_url?: string;
      provider?: string;
      default_branch?: string;
    },
  ) =>
    req<void>(`/api/projects/${id}`, {
      method: "PATCH",
      body: JSON.stringify(updates),
    }),

  updateProjectGitHubToken: (id: string, token: string) =>
    req<void>(`/api/projects/${id}/github-token`, {
      method: "PUT",
      body: JSON.stringify({ token }),
    }),

  deleteProject: (id: string) =>
    req<void>(`/api/projects/${id}`, { method: "DELETE" }),

  getTeams: () => req<Team[]>("/api/teams"),

  createTeam: (name: string) =>
    req<Team>("/api/teams", {
      method: "POST",
      body: JSON.stringify({ name }),
    }),

  deleteTeam: (id: string) =>
    req<void>(`/api/teams/${id}`, { method: "DELETE" }),

  addTeamMember: (teamId: string, userId: string) =>
    req<void>(`/api/teams/${teamId}/members`, {
      method: "POST",
      body: JSON.stringify({ user_id: userId }),
    }),

  removeTeamMember: (teamId: string, userId: string) =>
    req<void>(`/api/teams/${teamId}/members/${userId}`, { method: "DELETE" }),

  // Policies
  getPolicies: () => req<Policy[]>("/api/policies"),
  createPolicy: (data: {
    name: string;
    conditions: PolicyCondition[];
    actions: PolicyAction[];
  }) =>
    req<Policy>("/api/policies", {
      method: "POST",
      body: JSON.stringify(data),
    }),
  updatePolicy: (id: string, enabled: boolean) =>
    req<{ enabled: boolean }>(`/api/policies/${id}`, {
      method: "PATCH",
      body: JSON.stringify({ enabled }),
    }),
  deletePolicy: (id: string) =>
    req<void>(`/api/policies/${id}`, { method: "DELETE" }),

  // Suppressions
  getSuppressions: () => req<Suppression[]>("/api/suppressions"),
  createSuppression: (data: SuppressionCreate) =>
    req<Suppression>("/api/suppressions", {
      method: "POST",
      body: JSON.stringify(data),
    }),
  deleteSuppression: (id: string) =>
    req<void>(`/api/suppressions/${id}`, { method: "DELETE" }),

  // Audit Logs
  getAuditLogs: (entityType = "", action = "") =>
    req<{ logs: AuditLog[]; total: number }>(
      `/api/audit-logs?entity_type=${encodeURIComponent(entityType)}&action=${encodeURIComponent(action)}`,
    ),

  // Risk Acceptances
  getRiskAcceptances: (status = "", findingId = "") =>
    req<{ acceptances: RiskAcceptance[]; total: number }>(
      `/api/risk-acceptances?status=${encodeURIComponent(status)}&finding_id=${encodeURIComponent(findingId)}`,
    ),
  createRiskAcceptance: (data: { finding_id: string; rationale: string; expires_at: string }) =>
    req<RiskAcceptance>("/api/risk-acceptances", {
      method: "POST",
      body: JSON.stringify(data),
    }),
  approveRiskAcceptance: (id: string, reviewNotes: string) =>
    req<void>(`/api/risk-acceptances/${id}/approve`, {
      method: "POST",
      body: JSON.stringify({ review_notes: reviewNotes }),
    }),
  rejectRiskAcceptance: (id: string, reviewNotes: string) =>
    req<void>(`/api/risk-acceptances/${id}/reject`, {
      method: "POST",
      body: JSON.stringify({ review_notes: reviewNotes }),
    }),
  getRiskAcceptanceByFinding: (findingId: string) =>
    req<RiskAcceptance>(`/api/findings/${findingId}/risk-acceptance`),

  getWebhooks: () => req<Webhook[]>("/api/webhooks"),
  createWebhook: (data: WebhookCreate) =>
    req<Webhook>("/api/webhooks", {
      method: "POST",
      body: JSON.stringify(data),
    }),
  updateWebhook: (id: string, data: WebhookUpdate) =>
    req<Webhook>(`/api/webhooks/${id}`, {
      method: "PATCH",
      body: JSON.stringify(data),
    }),
  deleteWebhook: (id: string) =>
    req<void>(`/api/webhooks/${id}`, { method: "DELETE" }),
  testWebhook: (id: string) =>
    req<{ status: string; message: string }>(`/api/webhooks/${id}/test`, {
      method: "POST",
    }),

  getNotificationSettings: () =>
    req<NotificationSettings>("/api/settings/notifications"),
  updateNotificationSettings: (data: Partial<NotificationSettings>) =>
    req<NotificationSettings>("/api/settings/notifications", {
      method: "PATCH",
      body: JSON.stringify(data),
    }),
  testNotificationEmail: () =>
    req<{ status: string; message: string }>(
      "/api/settings/notifications/test-email",
      {
        method: "POST",
      },
    ),

  getJiraIntegration: () => req<JiraIntegration>("/api/integrations/jira"),
  updateJiraIntegration: (data: JiraIntegrationUpdate) =>
    req<JiraIntegration>("/api/integrations/jira", {
      method: "PUT",
      body: JSON.stringify(data),
    }),

  getFindingJiraIssue: (id: string) =>
    req<JiraIssueLink>(`/api/findings/${id}/jira`),
  createFindingJiraIssue: (id: string) =>
    req<JiraIssueLink>(`/api/findings/${id}/jira`, {
      method: "POST",
    }),

  getScannerPacks: () => req<ScannerPack[]>("/api/scanner-packs"),

  getSchedules: (projectID?: string) =>
    req<ScanSchedule[]>(`/api/schedules${projectID ? `?project_id=${projectID}` : ''}`),
  getSchedule: (id: string) =>
    req<ScanSchedule>(`/api/schedules/${id}`),
  createSchedule: (data: { project_id: string; scanner: string; cron_expr: string }) =>
    req<ScanSchedule>("/api/schedules", {
      method: "POST",
      body: JSON.stringify(data),
    }),
  updateSchedule: (id: string, data: { scanner?: string; cron_expr?: string; enabled?: boolean }) =>
    req<ScanSchedule>(`/api/schedules/${id}`, {
      method: "PATCH",
      body: JSON.stringify(data),
    }),
  deleteSchedule: (id: string) =>
    req<void>(`/api/schedules/${id}`, { method: "DELETE" }),
};

export interface MetricsSummary {
  total_scans: number;
  active_scans: number;
  total_findings: number;
  findings_by_severity: Record<string, number>;
  scans_by_scanner: Record<string, number>;
  recent_scans: Scan[];
}

export interface Scan {
  id: string;
  target: string;
  scanner: string;
  status: "pending" | "running" | "completed" | "failed";
  finding_count: number;
  created_at: string;
  started_at?: string;
  completed_at?: string;
  error?: string;
  container_log?: string;
}

export interface Finding {
  id: string;
  scan_id: string;
  scanner: string;
  rule_id: string;
  title: string;
  description: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  file_path: string;
  line_start: number;
  line_end: number;
  snippet_start_line?: number;
  code_snippet?: string;
  created_at: string;
  status: "open" | "in_review" | "accepted_risk" | "fixed" | "verified";
  assigned_to?: string;
  false_positive: boolean;
  notes?: string;
  resolved_at?: string;
  sla_deadline?: string;
  cve_id?: string;
  cwe_id?: string;
  ai_analyzed?: boolean;
  ai_summary?: string;
  summary_state?: "none" | "pending" | "ready" | "failed";
  suppressed: boolean;
  remediation_slug?: string;
  jira_issue?: JiraIssueLink;
  confidence_score?: number | null;
  corroboration_count?: number;
}

export interface AgentAnalysis {
  id: string;
  finding_id: string;
  agent_type: string;
  confidence: number;
  fp_likelihood: "low" | "medium" | "high";
  reasoning: string;
  raw_output?: unknown;
  created_at: string;
  updated_at: string;
}

export interface PolicyCondition {
  field: "severity" | "scanner" | "rule_id" | "file_path";
  op: "eq" | "contains";
  value: string;
}

export interface PolicyAction {
  type: "set_status" | "assign";
  value: string;
}

export interface Policy {
  id: string;
  name: string;
  description: string;
  conditions: PolicyCondition[];
  actions: PolicyAction[];
  enabled: boolean;
  pack_type: string;
  compliance_controls: string[];
  created_at: string;
}

export interface Suppression {
  id: string;
  name: string;
  rule_id?: string;
  file_pattern?: string;
  scanner?: string;
  reason?: string;
  created_at: string;
}

export interface AuditLog {
  id: string;
  user_id: string;
  user_email: string;
  action: string;
  entity_type: string;
  entity_id: string;
  old_value?: any;
  new_value?: any;
  ip_address?: string;
  user_agent?: string;
  created_at: string;
}

export interface RiskAcceptance {
  id: string;
  finding_id: string;
  user_id: string;
  rationale: string;
  expires_at: string;
  approved_by?: string;
  approved_at?: string;
  status: string;
  review_notes?: string;
  created_at: string;
  updated_at: string;
}

export interface SLASummary {
  overdue: number;
  due_today: number;
  on_track: number;
  no_deadline: number;
}

export interface TrendPoint {
  date: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface RepoRiskScore {
  repo_id: string;
  repo_name: string;
  repo_url: string;
  project_id: string;
  project_name: string;
  app_id?: string;
  app_name?: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  score: number;
}

export interface SLACompliance {
  total: number;
  on_time: number;
  overdue: number;
  percent: number;
}

export interface User {
  id: string;
  username: string;
  email: string;
  role: "admin" | "analyst" | "viewer";
  created_at: string;
  last_login?: string;
}

export interface Team {
  id: string;
  name: string;
  created_at: string;
  members: User[];
}

export interface Article {
  id: string;
  slug: string;
  title: string;
  content_md: string;
  tags: string[];
  cwe_ids: string[];
  rule_ids: string[];
  scanner: string;
  auto_generated: boolean;
  created_at: string;
  updated_at: string;
}

export interface VulnSummary {
  vuln_id: string;
  cve_id?: string;
  cwe_id?: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  scanners: string[];
  affected_count: number;
  finding_count: number;
  open_count: number;
  fixed_count: number;
}

export interface App {
  id: string;
  name: string;
  description?: string;
  team_id?: string;
  team_name?: string;
  created_at: string;
  projects: Project[];
}

export interface Project {
  id: string;
  name: string;
  description?: string;
  app_id?: string;
  repo_url?: string;
  provider?: string;
  default_branch?: string;
  external_repo_id?: string;
  has_token?: boolean;
  created_at: string;
}

export interface TeamMetrics {
  team_id: string;
  team_name: string;
  app_count: number;
  project_count: number;
  repo_count: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  score: number;
  sla_compliance: number;
  last_scan_at?: string;
}

export interface AffectedRepo {
  repo_name: string;
  repo_url: string;
  finding_count: number;
  open_count: number;
  fixed_count: number;
  statuses: string[];
  assignees: string[];
  nearest_deadline?: string;
}

export interface Webhook {
  id: string;
  label: string;
  url: string;
  delivery_type: "generic" | "slack" | "discord";
  events: string[];
  enabled: boolean;
  last_delivery?: string;
  delivery_count: number;
  error_count: number;
  last_error?: string;
  created_at: string;
}

export interface WebhookCreate {
  label: string;
  url: string;
  delivery_type?: "generic" | "slack" | "discord";
  events: string[];
}

export interface WebhookUpdate {
  label?: string;
  url?: string;
  delivery_type?: "generic" | "slack" | "discord";
  events?: string[];
  enabled?: boolean;
}

export interface NotificationSettings {
  alert_critical: boolean;
  alert_high: boolean;
  alert_scan_complete: boolean;
  alert_scan_failed: boolean;
  alert_sla_breach: boolean;
  email_recipients: string[];
  updated_at: string;
}

export interface JiraIntegration {
  base_url: string;
  user_email: string;
  project_key: string;
  issue_type: string;
  labels: string[];
  enabled: boolean;
  has_token: boolean;
  token_masked?: string;
  updated_at: string;
}

export interface JiraIntegrationUpdate {
  base_url?: string;
  user_email?: string;
  project_key?: string;
  issue_type?: string;
  labels?: string[];
  enabled?: boolean;
  token?: string;
}

export interface ScannerPack {
  id: string;
  label: string;
  description: string;
  scanners: string[];
}

export interface ScanSchedule {
  id: string;
  project_id: string;
  scanner: string;
  cron_expr: string;
  enabled: boolean;
  last_run?: string;
  next_run?: string;
  created_at: string;
}

export interface JiraIssueLink {
  id: string;
  finding_id: string;
  issue_key?: string;
  issue_url?: string;
  status?: string;
  created_at: string;
}
