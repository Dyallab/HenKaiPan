package findings

import (
	"testing"

	"aspm/internal/assert"
	"aspm/internal/models"
)

func pointerTo[T any](v T) *T {
	return &v
}

func TestValidateValidationResult_Valid(t *testing.T) {
	result := &validationResult{
		Confidence:    0.85,
		FPLikelihood:  "low",
		Reasoning:     "This is a real vulnerability",
		CorrelatedIDs: []string{},
	}
	correlated := []models.Finding{}
	err := validateValidationResult(result, correlated)
	assert.NoError(t, err)
}

func TestValidateValidationResult_Nil(t *testing.T) {
	err := validateValidationResult(nil, nil)
	assert.NotNil(t, err)
}

func TestValidateValidationResult_ConfidenceTooLow(t *testing.T) {
	result := &validationResult{
		Confidence:   -0.1,
		FPLikelihood: "low",
		Reasoning:    "test",
	}
	err := validateValidationResult(result, nil)
	assert.NotNil(t, err)
}

func TestValidateValidationResult_ConfidenceTooHigh(t *testing.T) {
	result := &validationResult{
		Confidence:   1.5,
		FPLikelihood: "low",
		Reasoning:    "test",
	}
	err := validateValidationResult(result, nil)
	assert.NotNil(t, err)
}

func TestValidateValidationResult_InvalidFPLikelihood(t *testing.T) {
	result := &validationResult{
		Confidence:   0.5,
		FPLikelihood: "unknown",
		Reasoning:    "test",
	}
	err := validateValidationResult(result, nil)
	assert.NotNil(t, err)
}

func TestValidateValidationResult_EmptyReasoning(t *testing.T) {
	result := &validationResult{
		Confidence:   0.5,
		FPLikelihood: "medium",
		Reasoning:    "",
	}
	err := validateValidationResult(result, nil)
	assert.NotNil(t, err)
}

func TestValidateValidationResult_CorrelatedIDsMustExist(t *testing.T) {
	correlated := []models.Finding{
		{ID: "finding-1"},
		{ID: "finding-2"},
	}
	result := &validationResult{
		Confidence:    0.5,
		FPLikelihood:  "medium",
		Reasoning:     "some reasoning",
		CorrelatedIDs: []string{"finding-1", "finding-3"}, // finding-3 not in correlated
	}
	err := validateValidationResult(result, correlated)
	assert.NotNil(t, err)
}

func TestValidateValidationResult_AllFPLikelihoods(t *testing.T) {
	for _, fp := range []string{"low", "medium", "high"} {
		result := &validationResult{
			Confidence:   0.5,
			FPLikelihood: fp,
			Reasoning:    "reasoning",
		}
		err := validateValidationResult(result, nil)
		if err != nil {
			t.Errorf("fp_likelihood %q should be valid, got: %v", fp, err)
		}
	}
}

func TestBuildValidationPrompt(t *testing.T) {
	finding := &models.Finding{
		ID:          "finding-1",
		Scanner:     "semgrep",
		RuleID:      "rules-react.security.audit.axios-csrf",
		Title:       "CSRF vulnerability",
		Severity:    "high",
		Description: "axios request without CSRF token",
		FilePath:    "src/components/LoginForm.jsx",
		LineStart:   42,
		LineEnd:     42,
		CVEID:       pointerTo("CVE-2024-12345"),
		CWEID:       pointerTo("CWE-352"),
		CodeSnippet: "axios.post('/api/login', data)",
	}

	correlated := []models.Finding{
		{ID: "finding-2", Scanner: "gosec", RuleID: "G101", Severity: "medium", FilePath: "src/main.go", LineStart: 10},
	}

	prompt := buildValidationPrompt(finding, correlated)
	assert.NotEqual(t, "", prompt)

	// Verify key fields
	assert.True(t, contains(prompt, "finding-1"))
	assert.True(t, contains(prompt, "semgrep"))
	assert.True(t, contains(prompt, "CSRF vulnerability"))
	assert.True(t, contains(prompt, "CVE-2024-12345"))
	assert.True(t, contains(prompt, "CWE-352"))
	assert.True(t, contains(prompt, "finding-2"))
	assert.True(t, contains(prompt, "gosec"))
}

func TestBuildValidationPrompt_NoCorrelated(t *testing.T) {
	finding := &models.Finding{
		ID:      "finding-1",
		Scanner: "semgrep",
		RuleID:  "rule-1",
		Title:   "test",
	}

	prompt := buildValidationPrompt(finding, nil)
	assert.NotEqual(t, "", prompt)
	assert.True(t, contains(prompt, "No other scanners flagged"))
}

func TestBuildValidationPrompt_CodeSnippetLong(t *testing.T) {
	// > 1024 chars → label becomes "Full file content"
	longSnippet := ""
	for i := 0; i < 1025; i++ {
		longSnippet += "x"
	}
	finding := &models.Finding{
		ID:          "f-1",
		Scanner:     "test",
		RuleID:      "R1",
		Title:       "test",
		CodeSnippet: longSnippet,
	}
	prompt := buildValidationPrompt(finding, nil)
	assert.True(t, contains(prompt, "Full file content"))
}

func TestBuildValidationPrompt_CVEPointerHandling(t *testing.T) {
	finding := &models.Finding{
		ID:      "f-1",
		Scanner: "test",
		RuleID:  "R1",
		Title:   "test",
		// CVEID and CWEID are nil → should not include their sections
	}
	prompt := buildValidationPrompt(finding, nil)
	assert.NotEqual(t, "", prompt)
}
