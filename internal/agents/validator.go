package agents

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/tmc/langchaingo/llms"
	"github.com/tmc/langchaingo/llms/anthropic"

	"aspm/internal/models"
	"aspm/internal/repository"
)

const validatorModel = "claude-haiku-4-5-20251001"

type ValidatorAgent struct {
	llm      llms.Model
	agents   repository.AgentRepository
	findings repository.FindingRepository
}

func NewValidator(apiKey string, agentRepo repository.AgentRepository, findingRepo repository.FindingRepository) (*ValidatorAgent, error) {
	llm, err := anthropic.New(
		anthropic.WithToken(apiKey),
		anthropic.WithModel(validatorModel),
	)
	if err != nil {
		return nil, fmt.Errorf("init anthropic: %w", err)
	}
	return &ValidatorAgent{llm: llm, agents: agentRepo, findings: findingRepo}, nil
}

type analysisResult struct {
	Confidence    float64  `json:"confidence"`
	FPLikelihood  string   `json:"fp_likelihood"`
	Reasoning     string   `json:"reasoning"`
	CorrelatedIDs []string `json:"correlated_finding_ids"`
}

var submitAnalysisTool = llms.Tool{
	Type: "function",
	Function: &llms.FunctionDefinition{
		Name:        "submit_analysis",
		Description: "Submit the false positive analysis result for this finding",
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"confidence": map[string]any{
					"type":        "number",
					"description": "0.0-1.0 probability the finding is a real vulnerability (1.0 = definitely real, 0.0 = definitely FP)",
				},
				"fp_likelihood": map[string]any{
					"type":        "string",
					"enum":        []string{"low", "medium", "high"},
					"description": "false positive likelihood — low=likely real, medium=uncertain, high=likely FP",
				},
				"reasoning": map[string]any{
					"type":        "string",
					"description": "concise explanation of the analysis decision (1-3 sentences)",
				},
				"correlated_finding_ids": map[string]any{
					"type":        "array",
					"items":       map[string]any{"type": "string"},
					"description": "IDs of correlated findings that corroborate or contradict this finding",
				},
			},
			"required": []string{"confidence", "fp_likelihood", "reasoning"},
		},
	},
}

const systemPrompt = `You are an application security analyst specializing in reducing false positives from SAST/SCA/secret detection scanners.

Analyze the provided finding and determine whether it is a real vulnerability or a false positive.

Consider:
- Scanner confidence signals (rule ID, description quality)
- Code snippet context (is the vulnerability actually reachable/exploitable?)
- Corroboration: multiple scanners flagging the same location = higher confidence
- Common FP patterns: test files, mock data, commented code, dead code paths, benign patterns misidentified

Always call submit_analysis with your conclusion.`

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

	resp, err := v.llm.GenerateContent(ctx,
		[]llms.MessageContent{
			llms.TextParts(llms.ChatMessageTypeSystem, systemPrompt),
			llms.TextParts(llms.ChatMessageTypeHuman, prompt),
		},
		llms.WithTools([]llms.Tool{submitAnalysisTool}),
		llms.WithToolChoice(map[string]any{"type": "tool", "name": "submit_analysis"}),
		llms.WithMaxTokens(1024),
	)
	if err != nil {
		return nil, fmt.Errorf("llm call: %w", err)
	}

	result, err := parseToolCall(resp)
	if err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	rawBytes, _ := json.Marshal(result)

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

func parseToolCall(resp *llms.ContentResponse) (*analysisResult, error) {
	if len(resp.Choices) == 0 {
		return nil, fmt.Errorf("empty response from LLM")
	}
	for _, tc := range resp.Choices[0].ToolCalls {
		if tc.FunctionCall != nil && tc.FunctionCall.Name == "submit_analysis" {
			var result analysisResult
			if err := json.Unmarshal([]byte(tc.FunctionCall.Arguments), &result); err != nil {
				return nil, fmt.Errorf("unmarshal tool args: %w", err)
			}
			return &result, nil
		}
	}
	return nil, fmt.Errorf("submit_analysis tool not called by LLM")
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
		fmt.Fprintf(&b, "\n**Code snippet:**\n```\n%s\n```\n", f.CodeSnippet)
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
