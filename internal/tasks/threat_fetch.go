package tasks

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"aspm/internal/models"
	"aspm/internal/repository"
)

// Production manifest fetcher for threat-intel sync (issue #64).
//
// FetchManifestForProject replaces the ErrNoManifestSource stub: for GitHub
// projects it downloads the first well-known manifest found via the GitHub
// raw content API and returns it as (sourceFile, bytes) — MVP single
// manifest. Non-GitHub projects and missing manifests return a wrapped
// ErrNoManifestSource (typed skip, not error) so the sync continues with
// the next project. Fetched bytes dispatch through threats.ParseManifest
// first in syncProject (threatintel.go).

// manifestHTTPTimeout sits in the 10-30s band; the telemetry/KEV idiom
// (NewRequestWithContext + explicit client timeout) applies to every fetch.
const manifestHTTPTimeout = 15 * time.Second

// manifestMaxBytes caps a single manifest download (lockfiles can be large).
const manifestMaxBytes = 8 << 20

// githubAPIBase is the default GitHub REST API base (overridable in the core).
const githubAPIBase = "https://api.github.com"

// threatManifestPaths are probed in order; the first hit wins (MVP single).
var threatManifestPaths = []string{
	"package.json",
	"package-lock.json",
	"go.mod",
	"requirements.txt",
	"Cargo.lock",
	"poetry.lock",
	"pom.xml",
}

// FetchManifestForProject is the production ThreatSyncDeps.FetchManifest:
// it resolves the project GitHub token (per-project stored token, falling
// back to GITHUB_TOKEN for env-configured setups) and fetches via the
// default GitHub API base. Never hardcodes tokens.
func FetchManifestForProject(ctx context.Context, apps repository.AppRepository, project models.Project) (string, []byte, error) {
	return fetchProjectManifest(ctx, nil, "", project, resolveManifestToken(ctx, apps, project))
}

// resolveManifestToken returns the per-project stored GitHub token, or the
// GITHUB_TOKEN env fallback when the project has none. Empty means public
// repos only; callers must not fail on empty.
func resolveManifestToken(ctx context.Context, apps repository.AppRepository, project models.Project) string {
	if apps != nil && project.ID != "" {
		if tok, err := apps.GetProjectGitHubToken(ctx, project.ID); err == nil && tok != "" {
			return tok
		}
	}
	return os.Getenv("GITHUB_TOKEN")
}

// fetchProjectManifest is the injectable core: a nil client gets a
// manifestHTTPTimeout default, an empty apiBase selects githubAPIBase
// (tests pass an httptest server URL and never hit real github.com).
func fetchProjectManifest(ctx context.Context, client *http.Client, apiBase string, project models.Project, token string) (string, []byte, error) {
	owner, repo, branch, ok := parseGitHubRepo(project)
	if !ok {
		return "", nil, fmt.Errorf("threatintel: project %s has no github repo source: %w", project.ID, ErrNoManifestSource)
	}
	if client == nil {
		client = &http.Client{Timeout: manifestHTTPTimeout}
	}
	if apiBase == "" {
		apiBase = githubAPIBase
	}
	apiBase = strings.TrimSuffix(apiBase, "/")

	for _, mf := range threatManifestPaths {
		endpoint := fmt.Sprintf("%s/repos/%s/%s/contents/%s?ref=%s",
			apiBase, owner, repo, mf, url.QueryEscape(branch))
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return "", nil, fmt.Errorf("threatintel: build manifest request: %w", err)
		}
		// Raw media type: the contents API returns file bytes directly.
		req.Header.Set("Accept", "application/vnd.github.raw")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := client.Do(req)
		if err != nil {
			return "", nil, fmt.Errorf("threatintel: fetch %s: %w", mf, err)
		}
		body, status, readErr := readManifestBody(resp)
		if readErr != nil {
			return "", nil, readErr
		}
		if status == http.StatusNotFound {
			continue
		}
		if status >= 400 {
			return "", nil, fmt.Errorf("threatintel: fetch %s: github api http %d", mf, status)
		}
		if len(bytes.TrimSpace(body)) == 0 {
			continue
		}
		return mf, body, nil
	}
	return "", nil, fmt.Errorf("threatintel: no manifest found for project %s: %w", project.ID, ErrNoManifestSource)
}

// readManifestBody drains and closes the response, enforcing the size cap.
func readManifestBody(resp *http.Response) ([]byte, int, error) {
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, manifestMaxBytes+1))
	if err != nil {
		return nil, 0, fmt.Errorf("threatintel: read manifest body: %w", err)
	}
	if len(body) > manifestMaxBytes {
		return nil, 0, fmt.Errorf("threatintel: manifest exceeds %d bytes", manifestMaxBytes)
	}
	return body, resp.StatusCode, nil
}

// parseGitHubRepo derives owner/repo/branch from the project fields.
// ok=false means "not a GitHub repo" (typed skip): missing RepoURL,
// non-github provider, non-github host, or unparseable ref.
// Accepted ref shapes: https://github.com/owner/repo[.git][/...][#branch],
// git@github.com:owner/repo.git, github.com/owner/repo, and bare
// owner/repo (provider github or empty). A #branch fragment (clone idiom)
// is stripped; DefaultBranch selects the ref, defaulting to main.
func parseGitHubRepo(project models.Project) (owner, repo, branch string, ok bool) {
	if project.Provider != "" && !strings.EqualFold(strings.TrimSpace(project.Provider), "github") {
		return "", "", "", false
	}
	if project.RepoURL == nil {
		return "", "", "", false
	}
	raw := strings.TrimSpace(*project.RepoURL)
	if raw == "" {
		return "", "", "", false
	}
	// Strip #branch fragment (clone URL idiom).
	if idx := strings.Index(raw, "#"); idx != -1 {
		raw = strings.TrimSpace(raw[:idx])
	}
	var path string
	switch {
	case strings.HasPrefix(raw, "git@github.com:"):
		path = strings.TrimPrefix(raw, "git@github.com:")
	case strings.HasPrefix(raw, "https://github.com/") ||
		strings.HasPrefix(raw, "http://github.com/") ||
		strings.HasPrefix(raw, "github.com/"):
		rest := raw
		if idx := strings.Index(rest, "github.com/"); idx != -1 {
			rest = rest[idx+len("github.com/"):]
		}
		path = rest
	case isBareRepoRef(raw):
		path = raw
	default:
		// Any other absolute URL (gitlab, bitbucket, ...) or garbage.
		if strings.Contains(raw, "://") {
			return "", "", "", false
		}
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			return "", "", "", false
		}
		if !strings.EqualFold(u.Host, "github.com") && !strings.EqualFold(u.Host, "www.github.com") {
			return "", "", "", false
		}
		path = strings.TrimPrefix(u.EscapedPath(), "/")
	}
	path = strings.Trim(path, "/")
	// Tolerate tree/blob links: owner/repo/<extra...>.
	parts := strings.Split(path, "/")
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return "", "", "", false
	}
	owner, repo = parts[0], strings.TrimSuffix(parts[1], ".git")
	if !isRepoPathComponent(owner) || !isRepoPathComponent(repo) {
		return "", "", "", false
	}
	branch = strings.TrimSpace(project.DefaultBranch)
	if branch == "" {
		branch = "main"
	}
	return owner, repo, branch, true
}

// isBareRepoRef matches "owner/repo" with no scheme, host, or extra path.
func isBareRepoRef(s string) bool {
	if strings.Contains(s, "://") || strings.Contains(s, "@") || strings.ContainsAny(s, " \t\n?") {
		return false
	}
	parts := strings.Split(s, "/")
	if len(parts) != 2 {
		return false
	}
	return isRepoPathComponent(strings.TrimSuffix(parts[0], ".git")) &&
		isRepoPathComponent(strings.TrimSuffix(parts[1], ".git"))
}

// isRepoPathComponent allows GitHub owner/repo characters (alphanumeric
// plus . _ -); keeps garbage like "not a repo ref !!!" out.
func isRepoPathComponent(s string) bool {
	if s == "" || s == "." || s == ".." {
		return false
	}
	for _, r := range s {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-' {
			continue
		}
		return false
	}
	return true
}
