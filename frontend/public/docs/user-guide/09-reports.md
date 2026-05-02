# Reports

Executive reports with trend analysis, risk scoring, and export capabilities.

![Reports](/presentation/07-reports.png)

## Trend Charts

### Findings Over Time
Line chart showing total findings trend:
- X-axis: Date range (last 7, 30, 90 days or custom)
- Y-axis: Finding count
- Separate lines per severity

### Status Distribution
Pie or bar chart showing remediation progress:
- Open vs Fixed vs Verified
- Accepted Risk (false positives)

### Risk Score Trend
Calculated risk score over time based on:
- Severity weighting (Critical = 10, High = 5, Medium = 2, Low = 1)
- SLA breach penalties
- Remediation velocity

## SLA Compliance Report

Track SLA performance:
- % findings fixed within deadline
- Average time to remediate by severity
- Overdue findings list
- Team performance comparison

## Scanner Coverage

Which projects are being scanned:
- Projects without scans in last N days
- "Never scanned" badge
- Scanner failure rates
- Average scan duration

## Executive Summary

One-page snapshot for leadership:
- Total findings (breakdown by severity)
- Critical findings requiring immediate attention
- 7-day trend (up/down/flat)
- Top 3 projects by risk score
- SLA compliance percentage

## Export Options

### CSV Export
Full dataset with filters applied:
- All columns included
- Suitable for Excel, Google Sheets, BI tools

### PDF Report
Printable executive summary:
- Charts rendered as SVG
- Company branding
- Date range in header
- Print-optimized stylesheet

### Scheduled Delivery
Automated report delivery:
- Weekly email to stakeholders
- Slack message with summary
- Custom webhook integration

## Filter Controls

Reports respect global filters:
- Date range picker
- Severity selection
- Project / App scope
- Scanner type

## Risk Score Calculation

Formula:
```
risk_score = (
  critical_count * 10 +
  high_count * 5 +
  medium_count * 2 +
  low_count * 1
) + sla_breach_penalty
```

Higher scores indicate more security debt requiring attention.

## Comparative Analysis

Compare periods:
- This week vs last week
- This month vs last month
- Quarter-over-quarter trends

Identify if security posture is improving or degrading.

---

**Previous:** [← Knowledge Base](/dashboard/documentation?page=knowledge)  
**Next:** [System Status →](/dashboard/documentation?page=system)
