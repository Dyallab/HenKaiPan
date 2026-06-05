package ai

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
)

// DigestContext holds weekly metrics for AI narrative generation.
type DigestContext struct {
	TotalScans       int
	TotalFindings    int
	CriticalCount    int
	HighCount        int
	NewFindings      int
	ResolvedFindings int
	SLACompliancePct float64
	TopProjects      []DigestProjectEntry
	TopVulns         []DigestVulnEntry
}

// DigestProjectEntry represents a project within the digest context.
type DigestProjectEntry struct {
	Name          string
	FindingCount  int
	CriticalCount int
}

// DigestVulnEntry represents a top vulnerability within the digest context.
type DigestVulnEntry struct {
	Title    string
	Severity string
	Project  string
	CVE      string
}

const digestSystemPrompt = `You are a security executive assistant preparing a weekly digest for technical leadership. Write 3–5 sentences summarizing the week's security scan results. Be professional and actionable. Highlight the most critical findings first. Mention SLA compliance status. Use plain text — no markdown, no formatting.`

// GenerateDigestNarrative generates an AI-powered narrative for the weekly digest.
// Returns empty string on error (graceful degradation).
func GenerateDigestNarrative(ctx context.Context, dc DigestContext) string {
	prompt := buildDigestPrompt(dc)

	narrative, err := GenerateSummary(ctx, digestSystemPrompt, prompt)
	if err != nil {
		slog.Warn("generate digest narrative failed", "err", err)
		return ""
	}

	return strings.TrimSpace(narrative)
}

func buildDigestPrompt(dc DigestContext) string {
	var b strings.Builder

	b.WriteString("Weekly security scan digest:\n\n")
	b.WriteString(fmt.Sprintf("- Total scans: %d\n", dc.TotalScans))
	b.WriteString(fmt.Sprintf("- Total findings: %d\n", dc.TotalFindings))
	b.WriteString(fmt.Sprintf("- Critical findings: %d\n", dc.CriticalCount))
	b.WriteString(fmt.Sprintf("- High findings: %d\n", dc.HighCount))
	b.WriteString(fmt.Sprintf("- New findings this week: %d\n", dc.NewFindings))
	b.WriteString(fmt.Sprintf("- Resolved findings this week: %d\n", dc.ResolvedFindings))
	b.WriteString(fmt.Sprintf("- SLA compliance: %.1f%%\n", dc.SLACompliancePct))

	if len(dc.TopProjects) > 0 {
		b.WriteString("\nTop projects by finding count:\n")
		for _, p := range dc.TopProjects {
			b.WriteString(fmt.Sprintf("  - %s (%d findings, %d critical)\n", p.Name, p.FindingCount, p.CriticalCount))
		}
	}

	if len(dc.TopVulns) > 0 {
		b.WriteString("\nTop vulnerabilities:\n")
		for _, v := range dc.TopVulns {
			cve := v.CVE
			if cve == "" {
				cve = "N/A"
			}
			b.WriteString(fmt.Sprintf("  - [%s] %s (CVE: %s) — %s\n", v.Severity, v.Title, cve, v.Project))
		}
	}

	b.WriteString("\nWrite 3–5 sentences summarizing these weekly security scan results for an executive digest. Be professional and actionable. Highlight the most critical findings first. Mention SLA compliance status.")

	return b.String()
}
