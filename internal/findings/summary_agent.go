package findings

import (
	"context"
	"fmt"
	"strings"

	"aspm/internal/ai"
	"aspm/internal/findings/summarymeta"
	"aspm/internal/repository"
)

type SummaryAgent struct {
	findings repository.FindingRepository
	model    string
}

func NewSummaryAgent(findingRepo repository.FindingRepository, model string) *SummaryAgent {
	return &SummaryAgent{findings: findingRepo, model: model}
}

const summarySystemPrompt = `You are a security finding summarizer.

Write a concise 1-2 sentence description for a repeated scanner finding.

Rules:
- Explain what the finding means and why it matters.
- Do not mention a specific repository, company, or environment unless explicitly provided in the input.
- Do not use markdown, bullets, or code fences.
- Do not invent exploit details that are not supported by the finding metadata.
- Keep the tone factual and useful for an AppSec triage screen.
- Maximum length: 280 characters.`

func (s *SummaryAgent) Summarize(ctx context.Context, findingID string) (string, error) {
	source, err := s.findings.GetSummarySource(ctx, findingID)
	if err != nil {
		return "", fmt.Errorf("get summary source: %w", err)
	}
	if strings.TrimSpace(source.Description) != "" {
		return source.Description, nil
	}
	if strings.TrimSpace(source.AISummary) != "" {
		return source.AISummary, nil
	}

	prepared, err := s.findings.PrepareAISummary(ctx, findingID)
	if err != nil {
		return "", fmt.Errorf("prepare ai summary: %w", err)
	}
	if prepared == nil {
		return "", nil
	}
	if strings.TrimSpace(prepared.Summary) != "" {
		return prepared.Summary, nil
	}
	if prepared.Fingerprint == "" {
		return "", nil
	}

	meta := summarymeta.Build(source.Scanner, source.RuleID, source.Title, source.Raw)
	prompt := buildSummaryPrompt(source, meta)
	text, err := ai.GenerateTextWithModel(ctx, summarySystemPrompt, prompt, 220, s.model)
	if err != nil {
		_ = s.findings.MarkAISummaryFailed(ctx, prepared.Fingerprint)
		return "", fmt.Errorf("generate finding summary: %w", err)
	}

	summary := sanitizeSummary(text)
	if summary == "" {
		_ = s.findings.MarkAISummaryFailed(ctx, prepared.Fingerprint)
		return "", fmt.Errorf("empty generated summary")
	}
	if err := s.findings.StoreAISummary(ctx, prepared.Fingerprint, summary); err != nil {
		return "", fmt.Errorf("store ai summary: %w", err)
	}
	return summary, nil
}

func buildSummaryPrompt(source *repository.FindingSummarySource, meta summarymeta.Metadata) string {
	var b strings.Builder
	b.WriteString("Generate a reusable summary for this finding signature.\n\n")
	fmt.Fprintf(&b, "- Scanner: %s\n", source.Scanner)
	fmt.Fprintf(&b, "- Rule ID: %s\n", source.RuleID)
	fmt.Fprintf(&b, "- Title: %s\n", source.Title)
	fmt.Fprintf(&b, "- Severity: %s\n", source.Severity)
	if source.FilePath != "" {
		fmt.Fprintf(&b, "- Example path: %s\n", source.FilePath)
	}
	if meta.IssueType != "" {
		fmt.Fprintf(&b, "- Issue type: %s\n", meta.IssueType)
	}
	if meta.RawExcerpt != "" {
		fmt.Fprintf(&b, "- Raw scanner payload excerpt: %s\n", meta.RawExcerpt)
	}
	b.WriteString("\nReturn plain text only.")
	return b.String()
}

func sanitizeSummary(value string) string {
	value = strings.TrimSpace(value)
	value = strings.Trim(value, "`")
	value = strings.ReplaceAll(value, "\n", " ")
	value = strings.Join(strings.Fields(value), " ")
	if len(value) > 280 {
		value = strings.TrimSpace(value[:280])
	}
	return value
}
