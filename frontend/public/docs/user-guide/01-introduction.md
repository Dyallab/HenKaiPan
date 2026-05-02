# Welcome to HenKaiPan

HenKaiPan is an Application Security Posture Management (ASPM) platform designed to help engineering teams manage security scans, track findings, and maintain compliance readiness.

![Login](/presentation/01-login.png)

## What You Can Do

### 🛡️ Security Scanning
- Run multiple security scanners (Semgrep, Trivy, Gitleaks, Checkov, Nuclei, and more)
- Schedule automated scans on cron-based intervals
- View scan results with detailed execution logs

### 📊 Finding Management
- Centralized inventory of all security findings
- Triage workflow with status tracking (Open → In Review → Fixed → Verified)
- SLA deadlines based on severity (Critical: 24h, High: 72h, Medium: 30d, Low: 90d)
- Cross-scanner deduplication via SHA256 fingerprints

### 📈 Reporting & Compliance
- Executive reports with risk trends and metrics
- SOC 2 / ISO 27001 / PCI-DSS compliance mapping
- Control evidence collection and export

### 🔗 Integrations
- GitHub App for PR comments with findings
- Slack webhook notifications
- Jira ticket creation from findings
- Custom webhooks for any event

## Quick Start

1. **Create your first Project** — Connect a Git repository or add manually
2. **Configure a scan** — Select scanners (SAST, SCA, Secrets, IaC, Containers)
3. **Review findings** — Triage, assign, and track remediation
4. **Set up schedules** — Automate recurring scans

## Navigation Overview

| Section | Purpose |
|---------|---------|
| [Dashboard](/dashboard) | Health metrics, onboarding, recent activity |
| [Findings](/dashboard/findings) | All vulnerabilities across projects |
| [Scans](/dashboard/scans) | Scan execution, logs, scheduling |
| [Projects](/dashboard/projects) | Connected repositories, scan history |
| [Compliance](/dashboard/compliance) | Framework mapping, evidence export |
| [Settings](/dashboard/settings) | Integrations, users, policies, notifications |

---

**Next:** [Dashboard Overview →](/dashboard/documentation?page=dashboard)
