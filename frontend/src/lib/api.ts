const API_BASE = 'http://localhost:8080';

function getToken(): string | null {
  return typeof localStorage !== 'undefined' ? localStorage.getItem('aspm_token') : null;
}

async function req<T>(path: string, options?: RequestInit): Promise<T> {
  const token = getToken();
  const res = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(options?.headers ?? {}),
    },
  });
  if (res.status === 401) {
    localStorage.removeItem('aspm_token');
    window.location.href = '/login';
    throw new Error('unauthorized');
  }
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error(err.error ?? res.statusText);
  }
  return res.json();
}

export const api = {
  login: (username: string, password: string) =>
    req<{ token: string }>('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username, password }),
    }),

  getMetrics: () => req<MetricsSummary>('/api/metrics/summary'),

  getScans: (page = 1, limit = 20) =>
    req<{ scans: Scan[]; total: number }>(`/api/scans?page=${page}&limit=${limit}`),

  createScan: (target: string, scanner: string) =>
    req<{ ids: string[] }>('/api/scans', {
      method: 'POST',
      body: JSON.stringify({ target, scanner }),
    }),

  getScan: (id: string) => req<Scan>(`/api/scans/${id}`),

  getScanFindings: (id: string) => req<Finding[]>(`/api/scans/${id}/findings`),

  getFindings: (severity = '', scanner = '', page = 1, limit = 50, status = '', overdue = false, category = '', cve_id = '', suppressed = false) =>
    req<{ findings: Finding[]; total: number }>(
      `/api/findings?severity=${severity}&scanner=${scanner}&page=${page}&limit=${limit}&status=${status}&overdue=${overdue}&category=${category}&cve_id=${encodeURIComponent(cve_id)}&suppressed=${suppressed}`
    ),

  updateFinding: (id: string, updates: {
    status?: string;
    assigned_to?: string;
    false_positive?: boolean;
    notes?: string;
  }) =>
    req<Finding>(`/api/findings/${id}`, {
      method: 'PATCH',
      body: JSON.stringify(updates),
    }),

  getSLASummary: () => req<SLASummary>('/api/findings/sla'),

  getTrends: (days = 30) => req<TrendPoint[]>(`/api/metrics/trends?days=${days}`),
  getRiskScores: () => req<RepoRiskScore[]>('/api/metrics/risk'),
  getSLACompliance: () => req<SLACompliance>('/api/metrics/sla-compliance'),

  exportFindingsURL: (severity = '', scanner = '', status = '') =>
    `http://localhost:8080/api/findings/export?severity=${severity}&scanner=${scanner}&status=${status}`,

  getRepos: () => req<Repo[]>('/api/repos'),

  createRepo: (name: string, url: string) =>
    req<Repo>('/api/repos', {
      method: 'POST',
      body: JSON.stringify({ name, url }),
    }),

  getMe: () => req<User>('/api/me'),

  // Knowledge Center
  getArticles: (q = '', scanner = '', tag = '', cwe_id = '', rule_id = '') =>
    req<Article[]>(`/api/knowledge?q=${encodeURIComponent(q)}&scanner=${scanner}&tag=${encodeURIComponent(tag)}&cwe_id=${encodeURIComponent(cwe_id)}&rule_id=${encodeURIComponent(rule_id)}`),

  getArticle: (slug: string) =>
    req<Article>(`/api/knowledge/${slug}`),

  lookupArticle: (rule_id: string, cwe_id: string) =>
    req<{ found: boolean; article?: Article }>(`/api/knowledge/lookup?rule_id=${encodeURIComponent(rule_id)}&cwe_id=${encodeURIComponent(cwe_id)}`),

  aiRemediate: (finding_id: string) =>
    req<{ article: Article; cached: boolean }>('/api/knowledge/ai-remediate', {
      method: 'POST',
      body: JSON.stringify({ finding_id }),
    }),

  createArticle: (data: { title: string; content_md: string; tags: string[]; cwe_ids: string[]; rule_ids: string[]; scanner: string }) =>
    req<Article>('/api/knowledge', { method: 'POST', body: JSON.stringify(data) }),

  updateArticle: (slug: string, data: Partial<{ title: string; content_md: string; tags: string[]; cwe_ids: string[]; rule_ids: string[]; scanner: string }>) =>
    req<Article>(`/api/knowledge/${slug}`, { method: 'PUT', body: JSON.stringify(data) }),

  deleteArticle: (slug: string) =>
    req<void>(`/api/knowledge/${slug}`, { method: 'DELETE' }),

  getVulnerabilities: (severity = '', q = '', open = true, page = 1, limit = 100) =>
    req<{ vulnerabilities: VulnSummary[]; total: number }>(
      `/api/vulnerabilities?severity=${severity}&q=${encodeURIComponent(q)}&open=${open}&page=${page}&limit=${limit}`
    ),

  getVulnerabilityAffected: (vulnID: string) =>
    req<AffectedRepo[]>(`/api/vulnerabilities/${encodeURIComponent(vulnID)}/affected`),

  getUsers: () => req<User[]>('/api/users'),

  createUser: (username: string, email: string, password: string, role: string) =>
    req<User>('/api/users', {
      method: 'POST',
      body: JSON.stringify({ username, email, password, role }),
    }),

  updateUser: (id: string, updates: { email?: string; role?: string; password?: string }) =>
    req<User>(`/api/users/${id}`, {
      method: 'PATCH',
      body: JSON.stringify(updates),
    }),

  deleteUser: (id: string) =>
    req<void>(`/api/users/${id}`, { method: 'DELETE' }),

  getTeamMetrics: () => req<TeamMetrics[]>('/api/metrics/teams'),

  getApps: (teamId = '') => req<App[]>(`/api/apps${teamId ? `?team_id=${teamId}` : ''}`),

  createApp: (name: string, description: string, teamId: string | null) =>
    req<App>('/api/apps', {
      method: 'POST',
      body: JSON.stringify({ name, description, team_id: teamId }),
    }),

  updateApp: (id: string, updates: { name?: string; description?: string; team_id?: string }) =>
    req<void>(`/api/apps/${id}`, { method: 'PATCH', body: JSON.stringify(updates) }),

  deleteApp: (id: string) =>
    req<void>(`/api/apps/${id}`, { method: 'DELETE' }),

  createProject: (appId: string, name: string, description: string, repoId: string | null) =>
    req<Project>(`/api/apps/${appId}/projects`, {
      method: 'POST',
      body: JSON.stringify({ name, description, repo_id: repoId }),
    }),

  deleteProject: (appId: string, projectId: string) =>
    req<void>(`/api/apps/${appId}/projects/${projectId}`, { method: 'DELETE' }),

  getTeams: () => req<Team[]>('/api/teams'),

  createTeam: (name: string) =>
    req<Team>('/api/teams', {
      method: 'POST',
      body: JSON.stringify({ name }),
    }),

  deleteTeam: (id: string) =>
    req<void>(`/api/teams/${id}`, { method: 'DELETE' }),

  addTeamMember: (teamId: string, userId: string) =>
    req<void>(`/api/teams/${teamId}/members`, {
      method: 'POST',
      body: JSON.stringify({ user_id: userId }),
    }),

  removeTeamMember: (teamId: string, userId: string) =>
    req<void>(`/api/teams/${teamId}/members/${userId}`, { method: 'DELETE' }),

  // Policies
  getPolicies: () => req<Policy[]>('/api/policies'),
  createPolicy: (data: { name: string; conditions: PolicyCondition[]; actions: PolicyAction[] }) =>
    req<Policy>('/api/policies', { method: 'POST', body: JSON.stringify(data) }),
  updatePolicy: (id: string, enabled: boolean) =>
    req<{ enabled: boolean }>(`/api/policies/${id}`, { method: 'PATCH', body: JSON.stringify({ enabled }) }),
  deletePolicy: (id: string) =>
    req<void>(`/api/policies/${id}`, { method: 'DELETE' }),

  // Suppressions
  getSuppressions: () => req<Suppression[]>('/api/suppressions'),
  createSuppression: (data: { name: string; rule_id?: string; file_pattern?: string; scanner?: string; reason?: string }) =>
    req<Suppression>('/api/suppressions', { method: 'POST', body: JSON.stringify(data) }),
  deleteSuppression: (id: string) =>
    req<void>(`/api/suppressions/${id}`, { method: 'DELETE' }),
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
  status: 'pending' | 'running' | 'completed' | 'failed';
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
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  file_path: string;
  line_start: number;
  line_end: number;
  code_snippet?: string;
  created_at: string;
  status: 'open' | 'in_review' | 'accepted_risk' | 'fixed' | 'verified';
  assigned_to?: string;
  false_positive: boolean;
  notes?: string;
  resolved_at?: string;
  sla_deadline?: string;
  cve_id?: string;
  cwe_id?: string;
  suppressed: boolean;
  remediation_slug?: string;
}

export interface PolicyCondition {
  field: 'severity' | 'scanner' | 'rule_id' | 'file_path';
  op: 'eq' | 'contains';
  value: string;
}

export interface PolicyAction {
  type: 'set_status' | 'assign';
  value: string;
}

export interface Policy {
  id: string;
  name: string;
  conditions: PolicyCondition[];
  actions: PolicyAction[];
  enabled: boolean;
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

export interface Repo {
  id: string;
  name: string;
  url: string;
  created_at: string;
}

export interface User {
  id: string;
  username: string;
  email: string;
  role: 'admin' | 'analyst' | 'viewer';
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
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
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
  app_id: string;
  repo_id?: string;
  repo_name?: string;
  repo_url?: string;
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
