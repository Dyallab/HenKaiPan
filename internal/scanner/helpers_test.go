package scanner

import (
	"testing"

	"aspm/internal/assert"
)

func TestFirstCWE_Found(t *testing.T) {
	tests := []struct {
		name string
		tags []string
		want string
	}{
		{"direct match", []string{"CWE-79", "xss"}, "CWE-79"},
		{"lowercase", []string{"cwe-352"}, "CWE-352"},
		{"mixed case", []string{"Cwe-89"}, "CWE-89"},
		{"embedded in text", []string{"security", "CWE-79-xss"}, "CWE-79"},
		{"multiple", []string{"CWE-79", "CWE-89"}, "CWE-79"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, firstCWE(tt.tags))
		})
	}
}

func TestFirstCWE_NotFound(t *testing.T) {
	assert.Equal(t, "", firstCWE(nil))
	assert.Equal(t, "", firstCWE([]string{}))
	assert.Equal(t, "", firstCWE([]string{"security", "xss", "react"}))
	assert.Equal(t, "", firstCWE([]string{"CWE-notanumber", "random"}))
}

func TestFirstCVE_Found(t *testing.T) {
	tests := []struct {
		name       string
		candidates []string
		want       string
	}{
		{"direct CVE", []string{"CVE-2024-21626"}, "CVE-2024-21626"},
		{"lowercase", []string{"cve-2023-45857"}, "CVE-2023-45857"},
		{"first match", []string{"GHSA-xxxx", "CVE-2024-12345", "nothing"}, "CVE-2024-12345"},
		{"embedded", []string{"Vulnerability CVE-2024-21626 found"}, "CVE-2024-21626"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, firstCVE(tt.candidates...))
		})
	}
}

func TestFirstCVE_NotFound(t *testing.T) {
	assert.Equal(t, "", firstCVE())
	assert.Equal(t, "", firstCVE("GHSA-xxxx-xxxx-xxxx"))
	assert.Equal(t, "", firstCVE("nothing", "here"))
}

func TestNormalizeFindingPath(t *testing.T) {
	tests := []struct {
		name string
		path string
		want string
	}{
		{"empty", "", ""},
		{"already absolute", "/src/main.go", "/main.go"},
		{"strip file://", "file:///src/main.go", "/main.go"},
		{"relative", "relative/path.go", "/relative/path.go"},
		{"strip /src/ prefix", "/src/app/main.go", "/app/main.go"},
		{"strip src/ prefix", "src/main.go", "/main.go"},
		{"URL passthrough", "https://example.com", "https://example.com"},
		{"URL with file scheme passthrough", "s3://bucket/key", "s3://bucket/key"},
		{"with spaces", "  /src/main.go", "/main.go"},
		{"just spaces", "   ", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, normalizeFindingPath(tt.path))
		})
	}
}

func TestCvssToSeverity(t *testing.T) {
	tests := []struct {
		name  string
		score string
		want  string
	}{
		{"critical 10", "10", "critical"},
		{"critical 9.0", "9.0", "critical"},
		{"critical 9.5", "9.5", "critical"},
		{"high 8.9", "8.9", "high"},
		{"high 7.0", "7.0", "high"},
		{"high 7.5", "7.5", "high"},
		{"medium 6.9", "6.9", "medium"},
		{"medium 4.0", "4.0", "medium"},
		{"low 3.9", "3.9", "low"},
		{"low 0.1", "0.1", "low"},
		{"info 0", "0", "info"},
		{"invalid empty", "", ""},
		{"invalid nan", "not-a-number", ""},
		{"negative", "-1", "info"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, cvssToSeverity(tt.score))
		})
	}
}

func TestParseTrivyMessage_AllFields(t *testing.T) {
	msg := "Package: runc\nInstalled Version: 1.1.11\nVulnerability CVE-2024-21626\nSeverity: CRITICAL\nFixed Version: 1.1.12"
	pkg, ver, fixed, sev := parseTrivyMessage(msg)
	assert.Equal(t, "runc", pkg)
	assert.Equal(t, "1.1.11", ver)
	assert.Equal(t, "1.1.12", fixed)
	assert.Equal(t, "critical", sev)
}

func TestParseTrivyMessage_Partial(t *testing.T) {
	msg := "Package: express\nSeverity: HIGH\nSome other line"
	pkg, ver, fixed, sev := parseTrivyMessage(msg)
	assert.Equal(t, "express", pkg)
	assert.Equal(t, "", ver)
	assert.Equal(t, "", fixed)
	assert.Equal(t, "high", sev)
}

func TestParseTrivyMessage_Empty(t *testing.T) {
	pkg, ver, fixed, sev := parseTrivyMessage("")
	assert.Equal(t, "", pkg)
	assert.Equal(t, "", ver)
	assert.Equal(t, "", fixed)
	assert.Equal(t, "", sev)
}

func TestSarifLevel(t *testing.T) {
	tests := []struct {
		name  string
		level string
		want  string
	}{
		{"error -> high", "error", "high"},
		{"warning -> medium", "warning", "medium"},
		{"note -> low", "note", "low"},
		{"info -> low", "info", "low"},
		{"mixed case", "Error", "high"},
		{"unknown -> info", "unknown", "info"},
		{"empty -> info", "", "info"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, sarifLevel(tt.level))
		})
	}
}

func TestNormalizeGrype(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"CRITICAL", "CRITICAL", "critical"},
		{"High", "High", "high"},
		{"medium", "medium", "medium"},
		{"Low", "Low", "low"},
		{"unknown -> info", "Unknown", "info"},
		{"empty -> info", "", "info"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, normalizeGrype(tt.input))
		})
	}
}

func TestNormalizeCheckov(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"CRITICAL", "CRITICAL", "critical"},
		{"HIGH", "HIGH", "high"},
		{"Medium", "Medium", "medium"},
		{"low", "low", "low"},
		{"unknown -> medium (Checkov default)", "Unknown", "medium"},
		{"empty -> medium", "", "medium"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, normalizeCheckov(tt.input))
		})
	}
}
