package findings

import (
	"testing"

	"aspm/internal/assert"
	"aspm/internal/findings/summarymeta"
	"aspm/internal/repository"
)

func TestSanitizeSummary_Trims(t *testing.T) {
	assert.Equal(t, "hello", sanitizeSummary("  hello  "))
}

func TestSanitizeSummary_RemovesBackticks(t *testing.T) {
	assert.Equal(t, "hello", sanitizeSummary("`hello`"))
	assert.Equal(t, "hello world", sanitizeSummary("`hello world`"))
}

func TestSanitizeSummary_ReplacesNewlines(t *testing.T) {
	assert.Equal(t, "hello world", sanitizeSummary("hello\nworld"))
}

func TestSanitizeSummary_CollapsesSpaces(t *testing.T) {
	assert.Equal(t, "a b c", sanitizeSummary("a   b   c"))
}

func TestSanitizeSummary_TruncatesAt280(t *testing.T) {
	long := ""
	for i := 0; i < 300; i++ {
		long += "x"
	}
	result := sanitizeSummary(long)
	assert.Equal(t, 280, len(result))
}

func TestSanitizeSummary_ShortStaysSame(t *testing.T) {
	assert.Equal(t, "hello world", sanitizeSummary("hello world"))
}

func TestSanitizeSummary_NewlineAndBackticks(t *testing.T) {
	input := "  `The finding\ndescription`  "
	assert.Equal(t, "The finding description", sanitizeSummary(input))
}

func TestBuildSummaryPrompt(t *testing.T) {
	source := &repository.FindingSummarySource{
		Scanner:     "semgrep",
		RuleID:      "rules-react.security.audit.axios-csrf",
		Title:       "CSRF vulnerability",
		Severity:    "high",
		FilePath:    "src/components/LoginForm.jsx",
	}
	meta := summarymeta.Metadata{
		Fingerprint: "abc123",
		IssueType:   "MissingAttribute",
		RawExcerpt:  `{"rule_id":"..."}`,
	}

	prompt := buildSummaryPrompt(source, meta)
	assert.NotEqual(t, "", prompt)

	// Verify key fields appear
	assert.True(t, contains(prompt, "semgrep"))
	assert.True(t, contains(prompt, "rules-react.security.audit.axios-csrf"))
	assert.True(t, contains(prompt, "CSRF vulnerability"))
	assert.True(t, contains(prompt, "high"))
	assert.True(t, contains(prompt, "src/components/LoginForm.jsx"))
	assert.True(t, contains(prompt, "MissingAttribute"))
	assert.True(t, contains(prompt, `{"rule_id":"..."}`))
}

func TestBuildSummaryPrompt_MinimalFields(t *testing.T) {
	source := &repository.FindingSummarySource{
		Scanner: "grype",
		RuleID:  "CVE-2024-21626",
		Title:   "runc breakout",
	}
	meta := summarymeta.Metadata{}

	prompt := buildSummaryPrompt(source, meta)
	assert.NotEqual(t, "", prompt)
	assert.True(t, contains(prompt, "grype"))
	assert.True(t, contains(prompt, "CVE-2024-21626"))
	assert.True(t, contains(prompt, "runc breakout"))
	// Without optional fields, should not include "Example path" or "Issue type" or "Raw scanner payload"
	assert.False(t, contains(prompt, "Example path"))
	assert.False(t, contains(prompt, "Issue type"))
	assert.False(t, contains(prompt, "Raw scanner payload"))
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && containsStr(s, substr)
}

func containsStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
