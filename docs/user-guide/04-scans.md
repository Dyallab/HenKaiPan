# Scans

The Scans page shows all security scan executions with logs, results, and scheduling configuration.

![Scans](/presentation/03-scans.png)

## Scan Types

### On-Demand Scans
Manually triggered scans for immediate results:
1. Click **Run Global Scan** in sidebar
2. Or go to a specific project and select scanners
3. Choose scanner pack: `all`, `sast`, `sca`, `secrets`, `iac`, `containers`
4. Scan is enqueued and executed by worker

### Scheduled Scans
Automated recurring scans via cron-based scheduling:
- Configure per-project in Schedules page
- Supports any valid cron expression
- Examples:
  - `0 2 * * *` — daily at 2 AM
  - `0 0 * * 1` — weekly on Monday midnight
  - `0 */6 * * *` — every 6 hours

## Scan Status

| Status | Meaning |
|--------|---------|
| Pending | Queued, waiting for worker |
| Running | Scanner executing in Docker |
| Completed | Finished successfully |
| Failed | Error during execution |
| Cancelled | Manually stopped |

## Scan Results

### Execution Log
Real-time stdout/stderr from scanner container. Useful for debugging failures.

### Summary Cards
- Total findings by severity
- New findings since last scan
- Scan duration
- Files scanned count

### Findings Table
Detailed list of detected vulnerabilities with:
- Rule ID
- File path and line number
- Severity
- Description
- Link to Knowledge Base (if available)

## Scanner Packs

Pre-configured scanner groups:

| Pack | Scanners Included | Use Case |
|------|------------------|----------|
| `all` | All available scanners | Full security audit |
| `sast` | Semgrep, Gosec | Static analysis |
| `sca` | Trivy, Grype, OSV-Scanner | Dependency vulnerabilities |
| `secrets` | Gitleaks, TruffleHog | Leaked credentials |
| `iac` | Checkov, KICS | Infrastructure as Code |
| `containers` | Trivy, Grype | Container images |

## Scanner Runtime

Scanners execute in isolated Docker containers:
- Worker mounts `/var/run/docker.sock`
- Each scanner has dedicated image
- Results parsed and normalized to common schema
- Findings deduplicated via SHA256 fingerprint

## Troubleshooting Failed Scans

1. **Check execution log** — Look for error messages
2. **Verify Docker socket** — Worker must have access
3. **Check repository access** — GitHub token may be expired
4. **Review scanner requirements** — Some scanners need specific file types

## AI Validation (Optional)

If AI providers are configured, findings can be validated for:
- False positive likelihood
- Confidence score
- Suggested remediation priority

---

**Previous:** [← Findings](/dashboard/documentation?page=findings)  
**Next:** [Projects →](/dashboard/documentation?page=projects)
