package github

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Client struct {
	apiURL     string
	token      string
	httpClient *http.Client
}

func NewClient(apiURL, token string) *Client {
	apiURL = strings.TrimRight(strings.TrimSpace(apiURL), "/")
	if apiURL == "" {
		apiURL = "https://api.github.com"
	}
	return &Client{
		apiURL: apiURL,
		token:  strings.TrimSpace(token),
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

func (c *Client) PostPullRequestComment(ctx context.Context, owner, repo string, pullNumber int, body string) error {
	owner = strings.TrimSpace(owner)
	repo = strings.TrimSpace(repo)
	body = strings.TrimSpace(body)
	if c.token == "" || owner == "" || repo == "" || pullNumber < 1 || body == "" {
		return fmt.Errorf("github pr comment configuration incomplete")
	}

	endpoint, err := url.JoinPath(c.apiURL, "repos", owner, repo, "issues", fmt.Sprintf("%d", pullNumber), "comments")
	if err != nil {
		return fmt.Errorf("build github comments url: %w", err)
	}
	payload, err := json.Marshal(map[string]string{"body": body})
	if err != nil {
		return fmt.Errorf("marshal github comment: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("create github comment request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "HenKaiPan-ASPM/1.0")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("send github comment request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("github comment failed: status %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	return nil
}

func ParseGitHubRepo(raw string) (owner string, repo string, ok bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", "", false
	}
	if path, ok := strings.CutPrefix(raw, "git@github.com:"); ok {
		return splitOwnerRepo(path)
	}
	parsed, err := url.Parse(raw)
	if err != nil || !strings.EqualFold(parsed.Hostname(), "github.com") {
		return "", "", false
	}
	return splitOwnerRepo(strings.TrimPrefix(parsed.Path, "/"))
}

func splitOwnerRepo(path string) (string, string, bool) {
	parts := strings.Split(strings.TrimSuffix(path, ".git"), "/")
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return "", "", false
	}
	return parts[0], parts[1], true
}
