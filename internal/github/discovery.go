package github

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const defaultLimit = 50

type RepoInfo struct {
	FullName      string `json:"full_name"`
	Name          string `json:"name"`
	Description   string `json:"description,omitempty"`
	RepoURL       string `json:"repo_url"`
	DefaultBranch string `json:"default_branch,omitempty"`
}

type ghRepo struct {
	FullName      string `json:"full_name"`
	Name          string `json:"name"`
	Description   string `json:"description"`
	HTMLURL       string `json:"html_url"`
	DefaultBranch string `json:"default_branch"`
}

type ghSearchResult struct {
	Items []ghRepo `json:"items"`
}

type ghError struct {
	Message string `json:"message"`
}

type ghUser struct {
	Login string `json:"login"`
	Name  string `json:"name"`
}

// TokenValidation holds the result of validating a GitHub PAT.
type TokenValidation struct {
	Valid     bool
	Login     string
	Scopes    []string
	ExpiresAt *time.Time
	Error     string
}

// ValidateToken checks if a GitHub PAT is valid and returns user info + scopes.
func ValidateToken(ctx context.Context, token string) TokenValidation {
	if token == "" {
		return TokenValidation{Valid: true}
	}

	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/user", nil)
	if err != nil {
		return TokenValidation{Error: fmt.Sprintf("build request: %v", err)}
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		return TokenValidation{Error: fmt.Sprintf("request failed: %v", err)}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, resp.Body)
		return TokenValidation{Error: fmt.Sprintf("invalid token (HTTP %d)", resp.StatusCode)}
	}

	var user ghUser
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return TokenValidation{Error: fmt.Sprintf("parse response: %v", err)}
	}

	var scopes []string
	if s := resp.Header.Get("X-OAuth-Scopes"); s != "" {
		for _, s := range strings.Split(s, ", ") {
			scopes = append(scopes, strings.TrimSpace(s))
		}
	}

	var expiresAt *time.Time
	if exp := resp.Header.Get("X-GitHub-Token-Expiration"); exp != "" {
		if t, err := time.Parse("2006-01-02 15:04:05 MST", exp); err == nil {
			expiresAt = &t
		} else if t, err := time.Parse(time.RFC3339, exp); err == nil {
			expiresAt = &t
		}
	}

	return TokenValidation{
		Valid:     true,
		Login:     user.Login,
		Scopes:    scopes,
		ExpiresAt: expiresAt,
	}
}

// ResolvePattern resolves a glob pattern to a list of GitHub repos.
//
// Supported patterns:
//   - "org/*"         → all public repos in the org
//   - "org/prefix-*"  → repos in org matching prefix
//   - "@user/*"       → all public repos in a user profile
//   - "@user/prefix-*" → repos in user profile matching prefix
//   - Any other       → GitHub search (q=pattern)
func ResolvePattern(ctx context.Context, pattern string, token string, limit int) ([]RepoInfo, error) {
	if limit <= 0 {
		limit = defaultLimit
	}

	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return nil, fmt.Errorf("pattern is required")
	}

	client := &http.Client{Timeout: 30 * time.Second}

	// @username/* pattern → user profile repos
	if strings.HasPrefix(pattern, "@") && strings.HasSuffix(pattern, "/*") {
		username := strings.TrimPrefix(pattern, "@")
		username = strings.TrimSuffix(username, "/*")
		if username == "" || strings.Contains(username, "/") {
			return nil, fmt.Errorf("invalid user pattern %q, expected @username/*", pattern)
		}
		return listUserRepos(ctx, client, username, "", token, limit)
	}

	// @username/prefix-* pattern
	if strings.HasPrefix(pattern, "@") {
		rest := strings.TrimPrefix(pattern, "@")
		if parts := strings.SplitN(rest, "/", 2); len(parts) == 2 && strings.Contains(parts[1], "*") {
			username := parts[0]
			prefix := strings.TrimRight(parts[1], "*")
			return listUserRepos(ctx, client, username, prefix, token, limit)
		}
	}

	// org/* pattern
	if strings.HasSuffix(pattern, "/*") {
		org := strings.TrimSuffix(pattern, "/*")
		if org == "" || strings.Contains(org, "/") {
			return nil, fmt.Errorf("invalid org pattern %q, expected org/*", pattern)
		}
		return listOrgRepos(ctx, client, org, "", token, limit)
	}

	// org/prefix-* pattern
	if parts := strings.SplitN(pattern, "/", 2); len(parts) == 2 && strings.Contains(parts[1], "*") {
		org := parts[0]
		prefix := strings.TrimRight(parts[1], "*")
		return listOrgRepos(ctx, client, org, prefix, token, limit)
	}

	// Single repo URL or full_name
	if strings.HasPrefix(pattern, "https://github.com/") {
		path := strings.TrimPrefix(pattern, "https://github.com/")
		path = strings.Trim(path, "/")
		parts := strings.SplitN(path, "/", 2)
		if len(parts) == 2 {
			pattern = parts[0] + "/" + parts[1]
		}
	}

	// Try as org/repo single lookup
	if parts := strings.SplitN(pattern, "/", 2); len(parts) == 2 && !strings.Contains(parts[1], "*") {
		repo, err := getSingleRepo(ctx, client, parts[0], parts[1], token)
		if err == nil {
			return []RepoInfo{*repo}, nil
		}
	}

	// Fallback: search
	return searchRepos(ctx, client, pattern, token, limit)
}

func listRepos(ctx context.Context, client *http.Client, baseURL, label, prefix, token string, limit int) ([]RepoInfo, error) {
	var allRepos []RepoInfo
	page := 1

	for len(allRepos) < limit {
		url := fmt.Sprintf("%s?per_page=100&page=%d&sort=full_name", baseURL, page)
		var repos []ghRepo
		if err := ghGet(ctx, client, url, token, &repos); err != nil {
			if len(allRepos) == 0 {
				return nil, fmt.Errorf("fetch %s repos: %w", label, err)
			}
			break
		}
		if len(repos) == 0 {
			break
		}
		for _, r := range repos {
			if prefix == "" || strings.HasPrefix(r.Name, prefix) {
				allRepos = append(allRepos, toRepoInfo(r))
				if len(allRepos) >= limit {
					break
				}
			}
		}
		page++
	}

	return allRepos, nil
}

func listOrgRepos(ctx context.Context, client *http.Client, org, prefix, token string, limit int) ([]RepoInfo, error) {
	baseURL := fmt.Sprintf("https://api.github.com/orgs/%s/repos", org)
	return listRepos(ctx, client, baseURL, org, prefix, token, limit)
}

func listUserRepos(ctx context.Context, client *http.Client, username, prefix, token string, limit int) ([]RepoInfo, error) {
	baseURL := fmt.Sprintf("https://api.github.com/users/%s/repos", username)
	return listRepos(ctx, client, baseURL, username, prefix, token, limit)
}

func getSingleRepo(ctx context.Context, client *http.Client, owner, repo, token string) (*RepoInfo, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s", owner, repo)
	var r ghRepo
	if err := ghGet(ctx, client, url, token, &r); err != nil {
		return nil, err
	}
	info := toRepoInfo(r)
	return &info, nil
}

func searchRepos(ctx context.Context, client *http.Client, query, token string, limit int) ([]RepoInfo, error) {
	url := fmt.Sprintf("https://api.github.com/search/repositories?q=%s&per_page=%d&sort=stars&order=desc",
		strings.ReplaceAll(query, " ", "+"), limit)
	var result ghSearchResult
	if err := ghGet(ctx, client, url, token, &result); err != nil {
		return nil, fmt.Errorf("search repos: %w", err)
	}
	var repos []RepoInfo
	for _, r := range result.Items {
		repos = append(repos, toRepoInfo(r))
		if len(repos) >= limit {
			break
		}
	}
	return repos, nil
}

func ghGet(ctx context.Context, client *http.Client, url, token string, dest interface{}) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var errResp ghError
		if json.Unmarshal(body, &errResp) == nil && errResp.Message != "" {
			// Check for rate limiting
			if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
				if strings.Contains(errResp.Message, "rate limit") {
					return fmt.Errorf("GitHub API rate limit exceeded (token: %v)", token != "")
				}
			}
			return fmt.Errorf("GitHub API: %s", errResp.Message)
		}
		return fmt.Errorf("GitHub API: HTTP %d", resp.StatusCode)
	}

	return json.Unmarshal(body, dest)
}

func toRepoInfo(r ghRepo) RepoInfo {
	desc := r.Description
	if desc != "" {
		if len(desc) > 200 {
			desc = desc[:200]
		}
	}
	branch := r.DefaultBranch
	if branch == "" {
		branch = "main"
	}
	return RepoInfo{
		FullName:      r.FullName,
		Name:          r.Name,
		Description:   desc,
		RepoURL:       r.HTMLURL,
		DefaultBranch: branch,
	}
}
