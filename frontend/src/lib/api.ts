import { friendlyError } from "./toast";

export const API_BASE = import.meta.env.PUBLIC_API_BASE || "";

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
      const err = await res.json().catch(() => ({ message: res.statusText }));
      const errorMsg = err.message ?? err.error ?? res.statusText;
      const errorCode = err.code ?? "";
      console.error(`API Error [${res.status}]:`, errorMsg, "Path:", path);
      window.dispatchEvent(
        new CustomEvent("api-error", {
          detail: {
            message: friendlyError(errorMsg),
            status: res.status,
            code: errorCode,
            path,
            silent: res.status === 404,
          },
        }),
      );
      const e = new Error(errorMsg);
      (e as any).code = errorCode;
      (e as any).status = res.status;
      throw e;
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
  get: <T>(path: string) => req<T>(path, { method: "GET" }),
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

  createAppScan: (app_id: string, scanner: string) =>
    req<{ ids: string[] }>("/api/scans", {
      method: "POST",
      body: JSON.stringify({ app_id, scanner }),
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

  requestSummary: (id: string) =>
    req<{ status: string; finding_id: string }>(`/api/findings/${id}/summary`, {
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
    `${API_BASE}/api/findings/export?severity=${encodeURIComponent(serializeMultiValue(severity))}&scanner=${scanner}&status=${status}`,

  getMe: () => req<User>("/api/me"),

  getConfigStatus: () =>
    req<{
      ai: { remediation: boolean; summary: boolean; validation: boolean };
      email_enabled: boolean;
      frontend_url: boolean;
      webhook_secret: boolean;
    }>("/api/config/status"),

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
    engineType?: string,
    projectId?: string,
  ) => {
    const params = new URLSearchParams();
    const sev = serializeMultiValue(severity);
    if (sev) params.set("severity", sev);
    if (q) params.set("q", q);
    params.set("open", String(open));
    params.set("page", String(page));
    params.set("limit", String(limit));
    if (engineType) params.set("engine_type", engineType);
    if (projectId) params.set("project_id", projectId);
    return req<{ vulnerabilities: VulnSummary[]; total: number }>(
      `/api/vulnerabilities?${params.toString()}`,
    );
  },

  getVulnerabilityAffected: (vulnID: string) =>
    req<AffectedFinding[]>(
      `/api/vulnerabilities/${encodeURIComponent(vulnID)}/affected`,
    ),

  getVulnerabilityEngineSummary: () =>
    req<ProjectEngineSummary[]>(
      "/api/vulnerabilities/engine-summary",
    ),

  updateVulnerabilityStatus: (vulnID: string, status: string) =>
    req<VulnSummary>(
      `/api/vulnerabilities/${encodeURIComponent(vulnID)}/status`,
      { method: "PATCH", body: JSON.stringify({ status }) },
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

  createProject: (data: {
    name: string;
    description?: string;
    app_id?: string | null;
    repo_url?: string;
    provider?: string;
    default_branch?: string;
  }) =>
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
      app_id?: string | null;
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

  bulkCreateProjects: (data: {
    pattern: string;
    app_id?: string | null;
    github_token?: string;
    limit?: number;
  }) =>
    req<{
      created: number;
      skipped: number;
      errors: number;
      projects: Array<{
        name: string;
        repo_url: string;
        status: string;
        error?: string;
        project_id?: string;
      }>;
    }>("/api/projects/bulk", {
      method: "POST",
      body: JSON.stringify(data),
    }),

  bulkAssignProjects: (appId: string, projectIds: string[]) =>
    req<{ assigned: number }>("/api/projects/bulk-assign", {
      method: "POST",
      body: JSON.stringify({ app_id: appId, project_ids: projectIds }),
    }),

  getCoverageReport: (days?: number) =>
    req<CoverageReport>(`/api/coverage${days ? `?days=${days}` : ""}`),

  getFindingComments: (findingId: string) =>
    req<FindingComment[]>(`/api/findings/${findingId}/comments`),

  createFindingComment: (findingId: string, content: string) =>
    req<FindingComment>(`/api/findings/${findingId}/comments`, {
      method: "POST",
      body: JSON.stringify({ content }),
    }),

  deleteFindingComment: (commentId: number) =>
    req<void>(`/api/findings/comments/${commentId}`, { method: "DELETE" }),

  bulkUpdateFindings: (
    findingIds: string[],
    updates: {
      status?: string;
      assigned_to?: string;
      false_positive?: boolean;
    },
  ) =>
    req<{ updated: number }>(`/api/findings/bulk`, {
      method: "PATCH",
      body: JSON.stringify({ finding_ids: findingIds, ...updates }),
    }),

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
  createRiskAcceptance: (data: {
    finding_id: string;
    rationale: string;
    expires_at: string;
  }) =>
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
    req<ScanSchedule[]>(
      `/api/schedules${projectID ? `?project_id=${projectID}` : ""}`,
    ),
  getSchedule: (id: string) => req<ScanSchedule>(`/api/schedules/${id}`),
  createSchedule: (data: {
    project_id?: string;
    app_id?: string;
    scanner: string;
    scanner_type?: string | null;
    cron_expr: string;
  }) =>
    req<ScanSchedule>("/api/schedules", {
      method: "POST",
      body: JSON.stringify(data),
    }),
  updateSchedule: (
    id: string,
    data: {
      scanner?: string;
      scanner_type?: string | null;
      cron_expr?: string;
      enabled?: boolean;
    },
  ) =>
    req<ScanSchedule>(`/api/schedules/${id}`, {
      method: "PATCH",
      body: JSON.stringify(data),
    }),
  deleteSchedule: (id: string) =>
    req<void>(`/api/schedules/${id}`, { method: "DELETE" }),

  getUnreadNotificationCount: () =>
    req<{ count: number }>("/api/notifications/unread-count"),

  markNotificationAsRead: (id: string) =>
    req<void>(`/api/notifications/${id}/read`, { method: "PATCH" }),

  markAllNotificationsAsRead: () =>
    req<void>("/api/notifications/read-all", { method: "PATCH" }),

  getNotifications: (params?: {
    page?: number;
    limit?: number;
    read?: boolean;
  }) => {
    const qs = new URLSearchParams();
    if (params?.page) qs.set("page", params.page.toString());
    if (params?.limit) qs.set("limit", params.limit.toString());
    if (params?.read !== undefined) qs.set("read", params.read.toString());
    return req<{ notifications: any[]; total: number }>(
      `/api/notifications?${qs}`,
    );
  },

  getLicense: () => req<License>("/api/license"),

  // ── API Tokens (CI/CD integration) ───────────────────────────────────
  getTokens: () => req<{ tokens: any[] }>("/api/v1/tokens"),
  createToken: (data: { name: string; project_id?: string }) =>
    req<{ token: string; id: string; name: string; prefix: string }>(
      "/api/v1/tokens",
      { method: "POST", body: JSON.stringify(data) },
    ),
  deleteToken: (id: string) =>
    req<void>(`/api/v1/tokens/${id}`, { method: "DELETE" }),
};

export interface Token {
  id: string;
  name: string;
  prefix: string;
  project_id?: string;
  created_by?: string;
  last_used_at?: string;
  expires_at?: string;
  created_at: string;
  updated_at: string;
}

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
  project_id?: string;
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
  pkg_name?: string;
  pkg_version?: string;
  corroborating_scanners?: string;
  vulnerability_id?: string;
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
  role: "admin" | "viewer";
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
  id: string;
  vuln_uid: string;
  project_id: string;
  title: string;
  description?: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  status: string;
  engine_type: string;
  pkg_name?: string;
  pkg_version?: string;
  cve_id?: string;
  cwe_id?: string;
  rule_id?: string;
  secret_hash?: string;
  file_path?: string;
  first_seen_at: string;
  last_seen_at: string;
  finding_count: number;
  scanner_coverage: string[];
  confidence_score?: number;
  created_at: string;
  updated_at: string;
}

export interface AffectedFinding {
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
  confidence_score?: number | null;
  corroboration_count: number;
  ai_analyzed: boolean;
  ai_summary?: string;
  summary_state?: string;
  suppressed: boolean;
  remediation_slug?: string;
  pkg_name?: string;
  pkg_version?: string;
  project_id: string;
  project_name: string;
  app_id?: string;
  app_name?: string;
  repo_url?: string;
}

export interface ProjectEngineSummary {
  project_id: string;
  project_name: string;
  app_id?: string;
  app_name?: string;
  by_engine: Record<string, number>;
  total_vulns: number;
  total_open: number;
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
  delivery_type: "generic" | "slack" | "discord";
  events: string[];
  enabled?: boolean;
}

export interface FindingComment {
  id: number;
  finding_id: string;
  user_id: string;
  username: string;
  content: string;
  created_at: string;
  updated_at: string;
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
  app_id?: string;
  scanner: string;
  scanner_type?: string | null;
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

export interface License {
  valid: boolean;
  status: string;
  expires_at?: string;
  features?: string[];
}

export interface ProjectCoverage {
  project_id: string;
  project_name: string;
  last_scan_at?: string;
  days_since_scan?: number;
  never_scanned: boolean;
}

export interface CoverageReport {
  total_projects: number;
  covered_projects: number;
  uncovered_projects: number;
  projects: ProjectCoverage[];
}
