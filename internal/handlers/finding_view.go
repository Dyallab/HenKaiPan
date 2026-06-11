package handlers

import (
	"strings"

	"aspm/internal/models"
)

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

