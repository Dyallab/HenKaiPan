package ai

import (
	"context"
	"log/slog"
	"strconv"
	"strings"
	"sync"
)

type NotificationContext struct {
	Severity    string
	Title       string
	RuleID      string
	Scanner     string
	Description string
	FilePath    string
	Line        int
	Repository  string
	EventType   string
}

type notificationSummaryCache struct {
	mu      sync.RWMutex
	entries map[string]string
}

var summaryCache = &notificationSummaryCache{entries: make(map[string]string)}

const notificationSystemPrompt = `You are a security alert writer for a developer dashboard. Write 2-3 sentences max. Be direct and actionable. Focus on what the code does wrong and how to fix it. No preamble, no references section.`

func GenerateNotificationSummary(ctx context.Context, nc NotificationContext) string {
	cacheKey := nc.RuleID + "|" + nc.Scanner

	summaryCache.mu.RLock()
	if cached, ok := summaryCache.entries[cacheKey]; ok {
		summaryCache.mu.RUnlock()
		return cached
	}
	summaryCache.mu.RUnlock()

	summary, err := GenerateSummary(ctx, notificationSystemPrompt, buildNotificationPrompt(nc))
	if err != nil {
		slog.Warn("generate notification summary failed", "rule_id", nc.RuleID, "scanner", nc.Scanner, "err", err)
		return ""
	}

	summaryCache.mu.Lock()
	summaryCache.entries[cacheKey] = summary
	summaryCache.mu.Unlock()

	return summary
}

func buildNotificationPrompt(nc NotificationContext) string {
	location := nc.FilePath
	if nc.Line > 0 {
		location = nc.FilePath + ":" + strconv.Itoa(nc.Line)
	}

	desc := strings.TrimSpace(nc.Description)
	if desc == "" {
		desc = "No description provided by scanner."
	}

	return strings.TrimSpace(`
Security finding detected in ` + nc.Repository + `:

- Severity: ` + nc.Severity + `
- Tool: ` + nc.Scanner + `
- Rule: ` + nc.RuleID + `
- Location: ` + location + `
- Title: ` + nc.Title + `
- Description: ` + desc + `

Write 2-3 sentences max explaining what this finding means for a developer and how to address it. Be direct. No preamble.
`)
}

