# Dashboard

The Dashboard is your security operations command center, providing real-time metrics and quick access to recent activity.

![Dashboard](/presentation/02-dashboard.png)

## Metrics Cards

### Total Findings
Aggregate count of all findings across all projects, broken down by severity:
- 🔴 Critical
- 🟠 High
- 🟡 Medium
- 🟢 Low

### Open vs Resolved
Track remediation progress with open findings vs fixed/verified count.

### SLA Compliance
Percentage of findings remediated within SLA deadlines. Critical findings must be fixed within 24 hours.

### Risk Score
Calculated risk based on severity distribution and SLA breaches.

## Severity Distribution Bar

Visual breakdown of findings by severity level. Click on any severity to filter the Findings page.

## Scanner Status

Shows which scanners are active and their recent execution status:
- 🟢 Success
- 🟡 Running
- 🔴 Failed

## Recent Scans

Last 10 scans executed across all projects with:
- Scanner type badge
- Target project name
- Status indicator
- Execution duration
- Findings count

## Onboarding Wizard

First-time users see a guided 3-step onboarding:
1. Create your first App (optional grouping)
2. Create a Project and connect a repository
3. Run your first scan

## Quick Actions

- **Run Global Scan** — Button in sidebar to immediately scan all projects
- **View Reports** — Navigate to executive reports with trend charts
- **Check Compliance** — See which controls have evidence coverage

---

**Previous:** [← Introduction](/dashboard/documentation?page=introduction)  
**Next:** [Findings Management →](/dashboard/documentation?page=findings)
