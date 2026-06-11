package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const maxPreviewLines = 400

// ExtractSnippet reads a file from a cloned git repository and returns a code
// snippet with context lines around the specified line range.
//
// For small files (≤ maxPreviewLines lines) the entire file is returned.
// For larger files, ±8 lines of context are included around [lineStart, lineEnd].
//
// Returns the snippet text, the 1-based start line of the returned snippet,
// and any error encountered.
func ExtractSnippet(repoDir, filePath string, lineStart, lineEnd int) (string, int, error) {
	if lineStart <= 0 {
		lineStart = 1
	}
	if lineEnd < lineStart {
		lineEnd = lineStart
	}

	relPath := normalizeSnippetPath(filePath)
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
	// Small file — return everything
	if len(lines) <= maxPreviewLines {
		return text, 1, nil
	}

	// Large file — return ±8 context lines around the finding
	contextBefore := 8
	contextAfter := 8
	start := max(lineStart-contextBefore, 1)
	end := min(lineEnd+contextAfter, len(lines))
	return strings.Join(lines[start-1:end], "\n"), start, nil
}

// normalizeSnippetPath strips common prefixes from scanner-reported file paths
// to produce a repo-relative path that can be joined with the clone directory.
func normalizeSnippetPath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	// Skip external URLs (e.g. https://github.com/...)
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
	return strings.TrimPrefix(path, "/")
}
