package jira

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type Client struct {
	baseURL    string
	userEmail  string
	apiToken   string
	httpClient *http.Client
}

type CreateIssueRequest struct {
	ProjectKey  string
	IssueType   string
	Summary     string
	Description string
	Labels      []string
}

type CreateIssueResponse struct {
	ID  string `json:"id"`
	Key string `json:"key"`
	Self string `json:"self"`
}

func NewClient(baseURL, userEmail, apiToken string) *Client {
	return &Client{
		baseURL:   strings.TrimRight(baseURL, "/"),
		userEmail: strings.TrimSpace(userEmail),
		apiToken:  strings.TrimSpace(apiToken),
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

func (c *Client) CreateIssue(ctx context.Context, req CreateIssueRequest) (*CreateIssueResponse, error) {
	payload := map[string]any{
		"fields": map[string]any{
			"project": map[string]string{
				"key": req.ProjectKey,
			},
			"issuetype": map[string]string{
				"name": req.IssueType,
			},
			"summary": req.Summary,
			"description": map[string]any{
				"type":    "doc",
				"version": 1,
				"content": []map[string]any{{
					"type": "paragraph",
					"content": []map[string]any{{
						"type": "text",
						"text": req.Description,
					}},
				}},
			},
		},
	}
	if len(req.Labels) > 0 {
		payload["fields"].(map[string]any)["labels"] = req.Labels
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal jira issue payload: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/rest/api/3/issue", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create jira request: %w", err)
	}
	auth := base64.StdEncoding.EncodeToString([]byte(c.userEmail + ":" + c.apiToken))
	httpReq.Header.Set("Authorization", "Basic "+auth)
	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("send jira issue request: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		trimmed := strings.TrimSpace(string(respBody))
		if trimmed == "" {
			trimmed = resp.Status
		}
		return nil, fmt.Errorf("jira create issue failed: %s", trimmed)
	}

	var out CreateIssueResponse
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, fmt.Errorf("decode jira issue response: %w", err)
	}
	return &out, nil
}
