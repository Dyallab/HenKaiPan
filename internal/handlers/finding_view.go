package handlers

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"aspm/internal/models"
)

const maxPreviewLines = 400

func normalizeDisplayPath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	if strings.Contains(path, "://") && !strings.HasPrefix(path, "file://") {
		return path
	}
	path = strings.TrimPrefix(path, "file://")
	if strings.HasPrefix(path, "/src/") {
		path = strings.TrimPrefix(path, "/src")
	}
	if strings.HasPrefix(path, "src/") {
		path = "/" + strings.TrimPrefix(path, "src/")
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return path
}

func shouldUseRuleIDAsTitle(f *models.Finding) bool {
	title := strings.TrimSpace(f.Title)
	description := strings.TrimSpace(f.Description)
	if title == "" {
		return true
	}
	trimmed := strings.TrimSuffix(title, "…")
	if trimmed == "" {
		return true
	}
	return strings.HasSuffix(title, "…") && description != "" && strings.HasPrefix(description, trimmed)
}

func humanizeRuleID(ruleID string) string {
	ruleID = strings.TrimSpace(ruleID)
	if ruleID == "" {
		return ""
	}
	segment := ruleID
	if idx := strings.LastIndex(segment, "."); idx >= 0 {
		segment = segment[idx+1:]
	}
	segment = strings.ReplaceAll(segment, "_", " ")
	segment = strings.ReplaceAll(segment, "-", " ")
	segment = strings.Join(strings.Fields(segment), " ")
	if segment == "" {
		return ruleID
	}
	return strings.ToUpper(segment[:1]) + segment[1:]
}

func (h *Handler) normalizeFindingForDisplay(f *models.Finding) {
	f.FilePath = normalizeDisplayPath(f.FilePath)
	if shouldUseRuleIDAsTitle(f) {
		if title := humanizeRuleID(f.RuleID); title != "" {
			f.Title = title
		}
	}
	if f.SnippetStartLine == 0 && f.CodeSnippet != "" {
		f.SnippetStartLine = f.LineStart
	}
}

func (h *Handler) enrichFindingCodeContext(ctx context.Context, target string, f *models.Finding) {
	if f == nil || f.LineStart <= 0 {
		return
	}
	if strings.Contains(f.FilePath, "://") {
		return
	}
	if strings.Count(f.CodeSnippet, "\n") > 1 {
		if f.SnippetStartLine == 0 {
			f.SnippetStartLine = f.LineStart
		}
		return
	}

	// Get the scan to find the project
	scan, err := h.store.Scans.Get(ctx, f.ScanID)
	if err != nil {
		return
	}

	// ProjectID is nullable - skip if no project
	if scan.ProjectID == nil {
		return
	}

	// Get the project to check for GitHub token
	project, err := h.store.Apps.GetProjectByID(ctx, *scan.ProjectID)
	if err != nil {
		return
	}

	// Build clone URL with token if available
	cloneURL := target
	if project.HasToken {
		token, err := h.store.Apps.GetProjectGitHubToken(ctx, project.ID)
		if err == nil && token != "" {
			// Inject token into HTTPS GitHub URL
			if strings.HasPrefix(target, "https://github.com/") {
				cloneURL = strings.Replace(target, "https://github.com/", "https://"+token+"@github.com/", 1)
			}
		}
	}

	cloneCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	dir, err := os.MkdirTemp("", "aspm-finding-view-")
	if err != nil {
		return
	}
	defer os.RemoveAll(dir)

	// Use GIT_ASKPASS=echo to prevent interactive prompts
	cmd := exec.CommandContext(cloneCtx, "git", "clone", "--depth=1", cloneURL, dir)
	cmd.Env = append(os.Environ(), "GIT_ASKPASS=echo")
	if err := cmd.Run(); err != nil {
		return
	}

	snippet, startLine, err := extractFindingSnippet(dir, f.FilePath, f.LineStart, f.LineEnd)
	if err != nil || snippet == "" {
		return
	}
	f.CodeSnippet = snippet
	f.SnippetStartLine = startLine
	if f.LineEnd == 0 {
		f.LineEnd = f.LineStart
	}
}

func extractFindingSnippet(repoDir, filePath string, lineStart, lineEnd int) (string, int, error) {
	if lineStart <= 0 {
		lineStart = 1
	}
	if lineEnd < lineStart {
		lineEnd = lineStart
	}
	relPath := strings.TrimPrefix(normalizeDisplayPath(filePath), "/")
	if relPath == "" {
		return "", 0, fmt.Errorf("empty file path")
	}

	fullPath := filepath.Join(repoDir, filepath.FromSlash(relPath))
	cleanPath := filepath.Clean(fullPath)
	cleanRepo := filepath.Clean(repoDir)
	if cleanPath != cleanRepo && !strings.HasPrefix(cleanPath, cleanRepo+string(os.PathSeparator)) {
		return "", 0, fmt.Errorf("invalid file path")
	}

	data, err := os.ReadFile(cleanPath)
	if err != nil {
		return "", 0, err
	}
	text := strings.ReplaceAll(string(data), "\r\n", "\n")
	lines := strings.Split(text, "\n")
	if len(lines) == 0 {
		return "", 0, fmt.Errorf("empty file")
	}
	if len(lines) <= maxPreviewLines {
		return text, 1, nil
	}

	contextBefore := 8
	contextAfter := 8
	start := max(lineStart-contextBefore, 1)
	end := min(lineEnd+contextAfter, len(lines))
	return strings.Join(lines[start-1:end], "\n"), start, nil
}
