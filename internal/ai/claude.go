package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

const apiURL = "https://api.anthropic.com/v1/messages"
const model  = "claude-haiku-4-5-20251001"

var apiKey string

// SetAPIKey must be called at startup. If empty, AI generation returns an error.
func SetAPIKey(k string) { apiKey = k }

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

func GenerateRemediation(ctx context.Context, req RemediationRequest) (string, error) {
	if apiKey == "" {
		return "", errors.New("ANTHROPIC_API_KEY not set")
	}

	prompt := buildPrompt(req)

	body, _ := json.Marshal(map[string]any{
		"model":      model,
		"max_tokens": 2048,
		"messages": []map[string]string{
			{"role": "user", "content": prompt},
		},
	})

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-key", apiKey)
	httpReq.Header.Set("anthropic-version", "2023-06-01")

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("anthropic API %d: %s", resp.StatusCode, string(raw))
	}

	var result struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(raw, &result); err != nil || len(result.Content) == 0 {
		return "", errors.New("unexpected response from Claude")
	}
	return result.Content[0].Text, nil
}

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

	return fmt.Sprintf(`You are an application security expert. A security scanner found the following vulnerability. Generate a concise, practical remediation guide in Markdown.

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
