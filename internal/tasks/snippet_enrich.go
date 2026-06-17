package tasks

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"aspm/internal/models"
	"aspm/internal/repository"
	"aspm/internal/scanner"
	"aspm/internal/validation"

	"github.com/hibiken/asynq"
)

const TypeSnippetEnrich = "finding:snippet-enrich"

type SnippetEnrichPayload struct {
	ScanID string `json:"scan_id"`
}

func MarshalSnippetEnrichPayload(p SnippetEnrichPayload) ([]byte, error) {
	return json.Marshal(p)
}

func UnmarshalSnippetEnrichPayload(data []byte) (SnippetEnrichPayload, error) {
	var p SnippetEnrichPayload
	return p, json.Unmarshal(data, &p)
}

// HandleSnippetEnrich processes a finding:snippet-enrich job.
// It clones the scanned repo (or re-uses the scan dir if still available),
// reads source files, and enriches findings that have short or empty code
// snippets with ±8 context lines.
//
// Errors are logged but never returned — the scan itself must not fail
// because of enrichment issues (best-effort).
func HandleSnippetEnrich(apps repository.AppRepository, scans repository.ScanRepository, findings repository.FindingRepository) asynq.HandlerFunc {
	return func(ctx context.Context, t *asynq.Task) error {
		p, err := UnmarshalSnippetEnrichPayload(t.Payload())
		if err != nil {
			return err
		}

		log := slog.With("scan_id", p.ScanID)
		log.Info("finding:snippet-enrich started")

		scan, err := scans.Get(ctx, p.ScanID)
		if err != nil {
			log.Warn("scan not found, skipping enrichment", "err", err)
			return nil
		}

		scanFindings, err := findings.GetByScanID(ctx, p.ScanID)
		if err != nil {
			log.Warn("failed to get findings for scan", "err", err)
			return nil
		}

		// Only enrich findings with empty or single-line snippets
		var toEnrich []models.Finding
		for _, f := range scanFindings {
			if strings.Count(f.CodeSnippet, "\n") <= 1 {
				toEnrich = append(toEnrich, f)
			}
		}

		if len(toEnrich) == 0 {
			log.Info("no findings to enrich")
			return nil
		}

		log.Info("enriching findings", "count", len(toEnrich))

		dir, err := cloneRepoForSnippet(ctx, apps, scan.ProjectID, scan.Target, p.ScanID)
		if err != nil {
			log.Warn("failed to clone repo for snippet enrichment", "err", err)
			return nil
		}
		defer os.RemoveAll(dir)

		enriched := 0
		for _, f := range toEnrich {
			if strings.Contains(f.FilePath, "://") {
				continue
			}
			if f.LineStart <= 0 {
				continue
			}

			snippet, _, err := scanner.ExtractSnippet(dir, f.FilePath, f.LineStart, f.LineEnd)
			if err != nil {
				log.Warn("extract snippet skipped", "finding_id", f.ID, "file", f.FilePath, "err", err)
				continue
			}
			if snippet == "" {
				continue
			}

			if err := findings.UpdateSnippet(ctx, f.ID, snippet, f.LineStart); err != nil {
				log.Warn("update snippet failed", "finding_id", f.ID, "err", err)
				continue
			}
			enriched++
		}

		log.Info("finding:snippet-enrich completed", "enriched", enriched, "total", len(toEnrich))
		return nil
	}
}

// cloneRepoForSnippet clones the target repository with --depth=1 for snippet
// enrichment. It attempts to use the project's GitHub token if available.
func cloneRepoForSnippet(ctx context.Context, apps repository.AppRepository, projectID *string, url, scanID string) (string, error) {
	// Defense-in-depth: validate target before git clone (SSRF prevention)
	if err := validation.ValidateGitTarget(url); err != nil {
		return "", fmt.Errorf("target validation failed: %w", err)
	}

	dir := filepath.Join(os.TempDir(), "aspm-snippet-"+scanID)

	if _, err := os.Stat(dir); err == nil {
		if rmErr := os.RemoveAll(dir); rmErr != nil {
			slog.Warn("failed to remove existing snippet dir", "dir", dir, "err", rmErr)
		}
	}

	var token string
	if projectID != nil && *projectID != "" {
		t, err := apps.GetProjectGitHubToken(ctx, *projectID)
		if err == nil && t != "" {
			token = t
		}
	}

	cloneURL := url
	var branch string
	if idx := strings.Index(cloneURL, "#"); idx != -1 {
		branch = cloneURL[idx+1:]
		cloneURL = cloneURL[:idx]
	}

	args := []string{"clone", "--depth=1"}
	if branch != "" {
		args = append(args, "--branch", branch)
	}

	authURL := cloneURL
	if token != "" {
		parsed := strings.TrimPrefix(cloneURL, "https://")
		parsed = strings.TrimPrefix(parsed, "http://")
		authURL = "https://" + token + "@" + parsed
	}

	args = append(args, authURL, dir)
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Env = append(os.Environ(), "GIT_ASKPASS=echo")
	out, err := cmd.CombinedOutput()
	if err != nil {
		os.RemoveAll(dir)
		return "", fmt.Errorf("git clone --depth=1: %w\n%s", err, out)
	}
	return dir, nil
}
