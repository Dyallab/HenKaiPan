# Projects

Projects are the primary technical unit in HenKaiPan. Each project represents a codebase you want to scan.

![Projects](/presentation/10-apps.png)

## Product Model

### Apps (Optional)
Business-level groupings for organizing projects:
- Example: "Mobile App", "Web Platform", "Internal Tools"
- Apps are optional — projects can exist standalone
- Useful for team-level rollups and filtering

### Projects
The core unit that you:
- Create manually or import from GitHub
- Connect to a Git repository
- Configure scans for
- Review findings from

## Creating a Project

### Via Onboarding Wizard
First-time users see a guided flow:
1. Create App (optional)
2. Enter project name
3. Connect GitHub repository or enter manually
4. Add GitHub token for private repos

### Manual Creation
1. Go to Projects page
2. Click **New Project**
3. Fill in:
   - Name (required)
   - App (optional)
   - Repository URL
   - GitHub token (for private repos, encrypted at rest)

## GitHub Integration

### GitHub App Installation
For automated PR comments:
1. Install HenKaiPan GitHub App on your org/repo
2. Link installation to project
3. Scans will comment on PRs with findings

### Personal Access Tokens
For scanning private repositories:
- Token stored encrypted in database
- Used during scanner execution
- Rotate tokens periodically

## Project Settings

### Scan Configuration
- Default scanner pack
- Scan schedule (cron expression)
- Notification rules

### Team Access
- Assign team members
- Set role-based permissions

## Scan History

Each project shows:
- Last scan date and status
- Total scans executed
- Findings trend over time
- Scanner failure rate

## Standalone Projects

Projects can exist without an App (`app_id = NULL`):
- Useful for small teams or single-repo setups
- Global Projects view shows all projects regardless of app

## Deleting Projects

⚠️ **Warning:** Deleting a project removes:
- All associated scans
- All findings
- Scan schedules
- Knowledge articles linked to findings

This action cannot be undone.

---

**Previous:** [← Scans](/dashboard/documentation?page=scans)  
**Next:** [Compliance →](/dashboard/documentation?page=compliance)
