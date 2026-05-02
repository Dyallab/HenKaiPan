# Compliance

The Compliance page maps your security findings to industry frameworks and helps collect audit evidence.

![Compliance](/presentation/08-compliance.png)

## Supported Frameworks

### SOC 2
Security, Availability, Processing Integrity, Confidentiality, Privacy trust principles.

### ISO 27001
Information security management system (ISMS) requirements.

### PCI-DSS
Payment Card Industry data security controls.

## Control Mapping

Findings are automatically mapped to relevant controls:

| Finding Type | SOC 2 | ISO 27001 | PCI-DSS |
|-------------|-------|-----------|---------|
| Hardcoded secrets | CC6.1 | A.9.2.4 | 8.2.1 |
| SQL injection | CC6.1 | A.14.2.5 | 6.5.1 |
| Outdated dependencies | CC7.1 | A.12.6.1 | 6.2 |
| Missing encryption | CC3.1 | A.10.1.1 | 4.1 |

## Evidence Collection

### Automated Evidence
- Scan execution logs
- Finding remediation timestamps
- Policy enforcement records
- User access audit logs

### Manual Evidence
Upload supporting documents:
- Security policies
- Procedure documentation
- Training records
- Third-party attestations

## Compliance Readiness Mode

Guided workflow for SOC 2 / ISO 27001 preparation:

1. **Gap Analysis** — Identify missing controls
2. **Policy Packs** — Pre-configured policies for common requirements
3. **Evidence Checklist** — Track what's collected vs pending
4. **Audit Export** — Generate TSV/CSV for auditors

## Risk Acceptance Workflow

For findings that cannot be immediately remediated:

1. Document business justification
2. Set review date (typically quarterly)
3. Obtain approval from security team
4. Track in audit log

## Control Testing

Schedule periodic tests for controls:
- Access reviews (quarterly)
- Penetration tests (annual)
- Vulnerability scans (continuous)

## Export Options

### TSV Format
Tab-separated values for easy import into audit tools.

### CSV Format
Comma-separated with full metadata.

### PDF Report
Executive summary with charts and control coverage.

---

**Previous:** [← Projects](/dashboard/documentation?page=projects)  
**Next:** [Settings →](/dashboard/documentation?page=settings)
