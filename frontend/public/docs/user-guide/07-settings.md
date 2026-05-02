# Settings

The Settings page configures integrations, users, policies, and system-wide behavior.

![Settings](/presentation/09-settings.png)

## General Settings

### Instance Configuration
- Instance name and branding
- Default timezone for schedules
- Session timeout duration

### Email Configuration
- SMTP server settings
- From address for notifications
- Test email button

## Integrations

### GitHub
- GitHub App installation status
- OAuth app credentials
- Default organization

### Slack
- Webhook URL for notifications
- Default channel
- Event subscriptions (new findings, SLA breaches)

### Jira
- Jira Cloud / Server URL
- API token
- Default project for tickets
- Field mapping (priority, labels)

### Custom Webhooks
- Endpoint URLs
- Event filters
- Retry policy (3 attempts with exponential backoff)
- Signature verification (HMAC-SHA256)

## Notifications

### Email Rules
Configure when to send emails:
- New critical findings
- SLA deadline approaching (24h warning)
- Weekly digest (every Monday)

### Slack Rules
- Real-time alerts for critical findings
- Daily summary at configurable time
- Mention on-call rotation

## Users & Teams

### User Management
- Invite new users (admin only)
- Assign roles: Admin, Analyst, Viewer
- Reset passwords
- Deactivate users

### Team Structure
- Create teams (e.g., "Backend", "DevOps", "Security")
- Assign members
- Team-based finding assignment

## Policies & Auto-Triage

### Policy Engine
Automated rules for finding handling:

**Conditions:**
- Scanner type
- Severity level
- File path pattern
- Rule ID
- CWE / CVE ID

**Actions:**
- Auto-assign to team
- Set status to "Accepted Risk"
- Add tags
- Trigger notification

### Example Policies
```
IF scanner = "gitleaks" AND severity = "high"
THEN assign to "security-team" AND notify slack

IF file_path starts with "test/" 
THEN set status = "accepted_risk"
```

### Suppressions
Temporarily disable policies for specific findings or time windows.

## Security

### Authentication
- JWT token expiration (default: 24h)
- Password complexity requirements
- Session concurrency limits

### Audit Log
View all user actions:
- Logins / logouts
- Finding status changes
- Policy modifications
- Integration updates

Filter by user, action type, or date range.

## License (Self-Hosted)

For self-hosted deployments:
- Enter license key
- View expiration date
- Feature flags enabled
- Support contact

---

**Previous:** [← Compliance](/dashboard/documentation?page=compliance)  
**Next:** [Knowledge Base →](/dashboard/documentation?page=knowledge)
