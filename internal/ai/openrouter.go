package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

const apiURL = "https://openrouter.ai/api/v1/chat/completions"
const defaultModel = "openai/gpt-4.1-mini"

var apiKey string
var model = defaultModel

// SetConfig must be called at startup. If apiKey is empty, AI generation returns an error.
func SetConfig(key, modelName string) {
	apiKey = strings.TrimSpace(key)
	if strings.TrimSpace(modelName) == "" {
		model = defaultModel
		return
	}
	model = strings.TrimSpace(modelName)
}

type RemediationRequest struct {
	RuleID      string
	Title       string
	Description string
	Severity    string
	Scanner     string
	FilePath    string
	CodeSnippet string
	CVEID       string
	CWEID       string
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatCompletionRequest struct {
	Model       string        `json:"model"`
	Messages    []chatMessage `json:"messages"`
	MaxTokens   int           `json:"max_tokens,omitempty"`
	Temperature float64       `json:"temperature,omitempty"`
}

type chatCompletionResponse struct {
	Choices []struct {
		Message struct {
			Content json.RawMessage `json:"content"`
		} `json:"message"`
	} `json:"choices"`
}

func GenerateRemediation(ctx context.Context, req RemediationRequest) (string, error) {
	prompt := buildPrompt(req)
	content, err := generateText(ctx, remediationSystemPrompt, prompt, 2048)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(content) == "" {
		return "", errors.New("empty remediation response from openrouter")
	}
	return content, nil
}

func GenerateJSON[T any](ctx context.Context, systemPrompt, userPrompt string, maxTokens int) (*T, error) {
	content, err := generateText(ctx, systemPrompt+"\n\nReturn a single JSON object only. Do not use markdown fences.", userPrompt, maxTokens)
	if err != nil {
		return nil, err
	}

	cleaned := strings.TrimSpace(content)
	var target T
	if err := json.Unmarshal([]byte(cleaned), &target); err == nil {
		return &target, nil
	}

	jsonObject, err := extractJSONObject(cleaned)
	if err != nil {
		return nil, fmt.Errorf("parse structured response: %w", err)
	}
	if err := json.Unmarshal([]byte(jsonObject), &target); err != nil {
		return nil, fmt.Errorf("unmarshal structured response: %w", err)
	}
	return &target, nil
}

func generateText(ctx context.Context, systemPrompt, userPrompt string, maxTokens int) (string, error) {
	if apiKey == "" {
		return "", errors.New("OPENROUTER_API_KEY not set")
	}

	body, err := json.Marshal(chatCompletionRequest{
		Model: configuredModel(),
		Messages: []chatMessage{
			{Role: "system", Content: systemPrompt},
			{Role: "user", Content: userPrompt},
		},
		MaxTokens:   maxTokens,
		Temperature: 0,
	})
	if err != nil {
		return "", fmt.Errorf("marshal openrouter request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("create openrouter request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+apiKey)
	httpReq.Header.Set("HTTP-Referer", "https://henkaipan.dyallab.com.ar")
	httpReq.Header.Set("X-Title", "HenKaiPan")

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("call openrouter: %w", err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read openrouter response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("openrouter API %d: %s", resp.StatusCode, string(raw))
	}

	var result chatCompletionResponse
	if err := json.Unmarshal(raw, &result); err != nil {
		return "", fmt.Errorf("decode openrouter response: %w", err)
	}
	if len(result.Choices) == 0 {
		return "", errors.New("empty response from openrouter")
	}

	content, err := parseMessageContent(result.Choices[0].Message.Content)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(content), nil
}

func parseMessageContent(raw json.RawMessage) (string, error) {
	var text string
	if err := json.Unmarshal(raw, &text); err == nil {
		return text, nil
	}

	var blocks []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if err := json.Unmarshal(raw, &blocks); err == nil {
		parts := make([]string, 0, len(blocks))
		for _, block := range blocks {
			if block.Text != "" {
				parts = append(parts, block.Text)
			}
		}
		if len(parts) == 0 {
			return "", errors.New("empty content blocks from openrouter")
		}
		return strings.Join(parts, "\n"), nil
	}

	return "", errors.New("unexpected response format from openrouter")
}

func extractJSONObject(content string) (string, error) {
	trimmed := strings.TrimSpace(content)
	trimmed = strings.TrimPrefix(trimmed, "```json")
	trimmed = strings.TrimPrefix(trimmed, "```")
	trimmed = strings.TrimSuffix(trimmed, "```")
	trimmed = strings.TrimSpace(trimmed)

	start := strings.Index(trimmed, "{")
	end := strings.LastIndex(trimmed, "}")
	if start == -1 || end == -1 || end < start {
		return "", errors.New("no JSON object found in response")
	}
	return trimmed[start : end+1], nil
}

func configuredModel() string {
	if model == "" {
		return defaultModel
	}
	return model
}

const remediationSystemPrompt = `You are an application security expert. Write concise, practical remediation guides in Markdown for developers. Prefer specific fixes over theory.`

func buildPrompt(req RemediationRequest) string {
	cveInfo := ""
	if req.CVEID != "" {
		cveInfo = fmt.Sprintf("\n- CVE: %s", req.CVEID)
	}
	cweInfo := ""
	if req.CWEID != "" {
		cweInfo = fmt.Sprintf("\n- CWE: %s", req.CWEID)
	}
	snippetSection := ""
	if req.CodeSnippet != "" {
		snippetSection = fmt.Sprintf("\n\n**Vulnerable code:**\n```\n%s\n```", req.CodeSnippet)
	}
	fileInfo := ""
	if req.FilePath != "" {
		fileInfo = fmt.Sprintf("\n- File: `%s`", req.FilePath)
	}

	return fmt.Sprintf(`A security scanner found the following vulnerability. Generate a concise, practical remediation guide in Markdown.

## Finding

- **Title:** %s
- **Rule ID:** %s
- **Scanner:** %s
- **Severity:** %s%s%s%s%s

**Description:**
%s

---

## Required output format (Markdown, no preamble)

## What is this vulnerability?
[2-3 sentence explanation of the root cause]

## Impact
[Business and technical impact, 2-4 bullet points]

## How to fix it
[Concrete code examples showing vulnerable vs fixed pattern. Use the same language as the affected file if detectable. Show before/after.]

## Detection & verification
[How to confirm the fix works — test snippet or manual check]

## References
[3-5 links: CWE, OWASP, scanner docs, language-specific guidance]

Keep the guide practical and focused. No lengthy theory. Target audience: developer who needs to fix this today.`,
		req.Title, req.RuleID, req.Scanner, req.Severity,
		cveInfo, cweInfo, fileInfo, snippetSection,
		req.Description,
	)
}
