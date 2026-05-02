# Findings Management

The Findings page is your central vulnerability inventory with triage, filtering, and export capabilities.

![Findings](/presentation/04-findings.png)

## Filters

### Severity Filter
Filter by one or multiple severity levels (Critical, High, Medium, Low, Info).

### Scanner Filter
Narrow down to findings from specific scanners:
- Semgrep (SAST)
- Trivy / Grype (SCA)
- Gitleaks / TruffleHog (Secrets)
- Checkov / KICS (IaC)
- Nuclei (DAST)

### Status Filter
View findings by triage state:
- Open
- In Review
- Accepted Risk
- Fixed
- Verified

### Project Filter
Scope findings to specific projects or apps.

## Findings Table

| Column | Description |
|--------|-------------|
| Severity | Color-coded badge (Critical → Low) |
| Title | Vulnerability name or CVE ID |
| Project | Target project name |
| Scanner | Which scanner detected it |
| File Path | Location in codebase |
| SLA Status | Days remaining / overdue indicator |
| Status | Current triage state |

## Triage Workflow

### 1. Review Finding Details
Click any finding to open the modal with:
- Full description
- Affected file and line number
- Scanner output
- CWE / CVE identifiers
- Confidence score

### 2. Set Status
Update the finding status:
- **Open** → newly detected, needs review
- **In Review** → being investigated
- **Accepted Risk** → false positive or won't fix (requires justification)
- **Fixed** → remediated, needs verification
- **Verified** → confirmed fixed in subsequent scan

### 3. Assign Owner
Assign to a team member for remediation.

### 4. Add Notes
Document investigation findings or remediation steps.

## SLA Tracking

Deadlines are auto-computed on finding creation:
- **Critical:** 24 hours
- **High:** 72 hours (3 days)
- **Medium:** 30 days
- **Low:** 90 days

Overdue findings are highlighted in red.

## Bulk Operations

Select multiple findings with checkboxes and:
- Change status in bulk
- Assign to user
- Export selected to CSV

## Export

Export filtered findings as CSV with all metadata for external reporting.

## Knowledge Base Integration

Findings with matching rule IDs link to Knowledge Base articles for remediation guidance.

---

**Previous:** [← Dashboard](/dashboard/documentation?page=dashboard)  
**Next:** [Scans →](/dashboard/documentation?page=scans)
