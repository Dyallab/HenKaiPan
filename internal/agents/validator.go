package agents

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"aspm/internal/ai"
	"aspm/internal/models"
	"aspm/internal/repository"
)

type ValidatorAgent struct {
	agents   repository.AgentRepository
	findings repository.FindingRepository
}

func NewValidator(agentRepo repository.AgentRepository, findingRepo repository.FindingRepository) *ValidatorAgent {
	return &ValidatorAgent{agents: agentRepo, findings: findingRepo}
}

type analysisResult struct {
	Confidence    float64  `json:"confidence"`
	FPLikelihood  string   `json:"fp_likelihood"`
	Reasoning     string   `json:"reasoning"`
	CorrelatedIDs []string `json:"correlated_finding_ids"`
}

const systemPrompt = `You are an application security analyst specializing in reducing false positives from SAST/SCA/secret detection scanners.

Analyze the provided finding and determine whether it is a real vulnerability or a false positive.

Scanner claims are often incorrect. Apply skepticism:
- MissingAttribute/AttributeNotFound findings are HIGHLY LIKELY FALSE POSITIVES - the scanner may have misparsed the file or missed the attribute
- "Hardcoded secret" findings on values that look like fake/test data = likely FP
- Findings on test files, mock data, commented code = likely FP
- Reachable/exploitable analysis: is the vulnerable code actually reachable in runtime?

For "MissingAttribute" findings specifically:
- The attribute is often present - scanner misparses YAML/HCL structures
- Consider if the CodeSnippet shows the attribute exists but scanner missed it
- Consider if the file was updated after scan
- Default to "medium" or "high" FP likelihood unless you have CONFIRMED the attribute is missing

Consider:
- Scanner confidence signals (rule ID, description quality)
- Code snippet context (is the vulnerability actually reachable/exploitable?)
- Corroboration: multiple scanners flagging the same location = higher confidence
- Common FP patterns: test files, mock data, commented code, dead code paths, benign patterns misidentified

Return a single JSON object with this exact shape:
{"confidence":0.0,"fp_likelihood":"low|medium|high","reasoning":"...","correlated_finding_ids":["..."]}

Rules:
- confidence must be a number between 0.0 and 1.0
- fp_likelihood must be one of low, medium, high
- reasoning must be concise (1-3 sentences)
- correlated_finding_ids must only include IDs from the provided correlated findings list`

func (v *ValidatorAgent) Analyze(ctx context.Context, findingID string) (*models.AgentAnalysis, error) {
	finding, err := v.findings.GetByID(ctx, findingID)
	if err != nil {
		return nil, fmt.Errorf("get finding: %w", err)
	}

	correlated, err := v.agents.GetCorrelatedFindings(ctx, findingID)
	if err != nil {
		return nil, fmt.Errorf("get correlations: %w", err)
	}

	prompt := buildPrompt(finding, correlated)

	result, err := ai.GenerateValidationJSON[analysisResult](ctx, systemPrompt, prompt)
	if err != nil {
		return nil, fmt.Errorf("ai validation: %w", err)
	}
	if err := validateAnalysisResult(result, correlated); err != nil {
		return nil, fmt.Errorf("validate response: %w", err)
	}

	rawBytes, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("marshal analysis result: %w", err)
	}

	analysis, err := v.agents.UpsertAnalysis(ctx, repository.AgentAnalysisInsert{
		FindingID:    findingID,
		AgentType:    "validator",
		Confidence:   result.Confidence,
		FPLikelihood: result.FPLikelihood,
		Reasoning:    result.Reasoning,
		RawOutput:    rawBytes,
	})
	if err != nil {
		return nil, fmt.Errorf("store analysis: %w", err)
	}

	if len(result.CorrelatedIDs) > 0 {
		if err := v.agents.InsertCorrelations(ctx, findingID, result.CorrelatedIDs, "same_signal"); err != nil {
			slog.Warn("insert correlations failed", "finding_id", findingID, "err", err)
		}
	}

	return analysis, nil
}

func validateAnalysisResult(result *analysisResult, correlated []models.Finding) error {
	if result == nil {
		return errors.New("missing analysis result")
	}
	if result.Confidence < 0 || result.Confidence > 1 {
		return fmt.Errorf("confidence out of range: %v", result.Confidence)
	}
	switch result.FPLikelihood {
	case "low", "medium", "high":
	default:
		return fmt.Errorf("invalid fp_likelihood: %q", result.FPLikelihood)
	}
	if strings.TrimSpace(result.Reasoning) == "" {
		return errors.New("missing reasoning")
	}

	allowed := make(map[string]struct{}, len(correlated))
	for _, finding := range correlated {
		allowed[finding.ID] = struct{}{}
	}
	for _, correlatedID := range result.CorrelatedIDs {
		if _, ok := allowed[correlatedID]; !ok {
			return fmt.Errorf("unknown correlated finding id: %s", correlatedID)
		}
	}

	return nil
}

func buildPrompt(f *models.Finding, correlated []models.Finding) string {
	var b strings.Builder

	fmt.Fprintf(&b, "## Finding to analyze\n\n")
	fmt.Fprintf(&b, "- **ID:** %s\n", f.ID)
	fmt.Fprintf(&b, "- **Scanner:** %s\n", f.Scanner)
	fmt.Fprintf(&b, "- **Rule:** %s\n", f.RuleID)
	fmt.Fprintf(&b, "- **Title:** %s\n", f.Title)
	fmt.Fprintf(&b, "- **Severity:** %s\n", f.Severity)
	fmt.Fprintf(&b, "- **File:** %s (lines %d–%d)\n", f.FilePath, f.LineStart, f.LineEnd)
	if f.CVEID != nil {
		fmt.Fprintf(&b, "- **CVE:** %s\n", *f.CVEID)
	}
	if f.CWEID != nil {
		fmt.Fprintf(&b, "- **CWE:** %s\n", *f.CWEID)
	}
	fmt.Fprintf(&b, "\n**Description:** %s\n", f.Description)

	if f.CodeSnippet != "" {
		label := "Code snippet"
		if len(f.CodeSnippet) > 1024 {
			label = "Full file content"
		}
		fmt.Fprintf(&b, "\n**%s:**\n```\n%s\n```\n", label, f.CodeSnippet)
	}

	if len(correlated) > 0 {
		fmt.Fprintf(&b, "\n## Correlated findings from other scanners (%d)\n\n", len(correlated))
		for _, c := range correlated {
			fmt.Fprintf(&b, "- ID: `%s` | Scanner: %s | Rule: %s | Severity: %s | File: %s:%d\n",
				c.ID, c.Scanner, c.RuleID, c.Severity, c.FilePath, c.LineStart)
		}
	} else {
		fmt.Fprintf(&b, "\n## Correlated findings\n\nNo other scanners flagged this location or rule.\n")
	}

	return b.String()
}
