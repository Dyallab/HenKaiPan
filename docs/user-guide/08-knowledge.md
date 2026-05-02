# Knowledge Base

The Knowledge Base contains remediation guides and security articles curated by your team or AI-generated.

![Knowledge](/presentation/06-knowledge.png)

## Article Types

### Curated Articles
Manually written by security team:
- Best practices
- Company-specific guidelines
- Technology stack recommendations

### AI-Generated Articles
Auto-created from findings:
- Triggered when user requests "AI Remediation"
- Generated from finding context (rule ID, file path, scanner output)
- Marked with AI badge

## Browsing Articles

### Search
Full-text search across:
- Title
- CVE / CWE IDs
- Scanner names
- Tags
- Content

### Filters
- **Scanner** — Show articles for specific scanner (e.g., Semgrep guides)
- **Tags** — Filter by topic (e.g., `path-traversal`, `go`, `file-inclusion`)

### Article List
Each article shows:
- Title
- Scanner badge
- CWE tags
- AI indicator (if auto-generated)
- Last updated date

## Article Structure

Articles include:
- **Title** — Clear, actionable headline
- **Scanner** — Which scanner this applies to
- **Rule IDs** — Matching scanner rules (e.g., `G304`, `G301`)
- **CWE IDs** — Linked to MITRE CWE database
- **Tags** — Topic keywords
- **Content** — Markdown with code examples

## Creating Articles (Admin Only)

1. Click **New Article** button
2. Fill in metadata:
   - Title (required)
   - Scanner
   - Rule IDs (comma-separated)
   - CWE IDs (comma-separated)
   - Tags (comma-separated)
3. Write content in Markdown
4. Toggle **Preview** to see rendered output
5. Click **Save Article**

## Editing Articles (Admin Only)

1. Open article
2. Click **Edit** button (admin only)
3. Modify content
4. Preview changes
5. Save updates

## Deleting Articles (Admin Only)

1. Open article
2. Click **Delete** button (trash icon)
3. Confirm deletion

⚠️ **Warning:** This action cannot be undone.

## AI Remediation Flow

From a finding:
1. Open finding modal
2. Click **Generate AI Remediation**
3. Article is created with:
   - Vulnerability explanation
   - Code fix example
   - Prevention tips
4. Article saved to Knowledge Base
5. Link appears in finding details

## Markdown Support

Articles support full Markdown:
- Headings (`##`, `###`)
- Code blocks with syntax highlighting (````go```, ````python```, etc.)
- Links and images
- Lists (ordered and unordered)
- Tables
- Blockquotes

## Integration with Findings

Findings automatically link to Knowledge Base articles when:
- Rule ID matches
- CWE ID matches
- Same scanner and similar title

---

**Previous:** [← Settings](/dashboard/documentation?page=settings)  
**Next:** [Reports →](/dashboard/documentation?page=reports)
