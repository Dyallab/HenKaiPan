package validation

import (
	"strings"
	"testing"

	"aspm/internal/assert"
)

func TestIsValid_Roles(t *testing.T) {
	tests := []struct {
		value string
		want  bool
	}{
		{"admin", true},
		{"viewer", true},
		{"superadmin", false},
		{"", false},
		{"Admin", false}, // case-sensitive
	}
	for _, tc := range tests {
		t.Run(tc.value, func(t *testing.T) {
			got := IsValid(Roles, tc.value)
			assert.Equal(t, got, tc.want)
		})
	}
}

func TestNormalizeWebhookDeliveryType(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"generic", "generic"},
		{"Generic", "generic"},
		{"GENERIC", "generic"},
		{"slack", "slack"},
		{"Slack", "slack"},
		{"SLACK", "slack"},
		{"discord", "discord"},
		{"Discord", "discord"},
		{"DISCORD", "discord"},
		{"teams", ""},
		{"", ""},
		{"unknown", ""},
	}
	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got := NormalizeWebhookDeliveryType(tc.input)
			assert.Equal(t, got, tc.want)
		})
	}
}

func TestValidateStruct_LoginRequest(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		errs := ValidateStruct(&LoginRequest{Username: "alice", Password: "secret123"})
		assert.Nil(t, errs)
	})

	t.Run("missing username", func(t *testing.T) {
		errs := ValidateStruct(&LoginRequest{Password: "secret123"})
		assert.NotNil(t, errs)
		assert.Equal(t, len(errs), 1)
		assert.Equal(t, errs[0].Field, "Username")
	})

	t.Run("missing password", func(t *testing.T) {
		errs := ValidateStruct(&LoginRequest{Username: "alice"})
		assert.NotNil(t, errs)
		assert.Equal(t, len(errs), 1)
		assert.Equal(t, errs[0].Field, "Password")
	})
}

func TestValidateStruct_CreateProjectRequest(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		errs := ValidateStruct(&CreateProjectRequest{
			Name:    "My Project",
			RepoURL: "https://github.com/org/repo",
		})
		assert.Nil(t, errs)
	})

	t.Run("missing name", func(t *testing.T) {
		errs := ValidateStruct(&CreateProjectRequest{})
		assert.NotNil(t, errs)
		assert.True(t, len(errs) >= 1)
	})

	t.Run("name too long", func(t *testing.T) {
		errs := ValidateStruct(&CreateProjectRequest{
			Name: strings.Repeat("a", 256),
		})
		assert.NotNil(t, errs)
	})

	t.Run("invalid repo url", func(t *testing.T) {
		errs := ValidateStruct(&CreateProjectRequest{
			Name:    "Test",
			RepoURL: "not-a-url",
		})
		assert.NotNil(t, errs)
	})
}

func TestValidateStruct_UpdateFindingRequest(t *testing.T) {
	t.Run("valid status", func(t *testing.T) {
		errs := ValidateStruct(&UpdateFindingRequest{Status: "open"})
		assert.Nil(t, errs)
	})

	t.Run("invalid status", func(t *testing.T) {
		errs := ValidateStruct(&UpdateFindingRequest{Status: "bogus"})
		assert.NotNil(t, errs)
	})

	t.Run("notes too long", func(t *testing.T) {
		errs := ValidateStruct(&UpdateFindingRequest{
			Status: "open",
			Notes:  strings.Repeat("a", 5001),
		})
		assert.NotNil(t, errs)
	})
}

func TestValidateStruct_CreateScanRequest(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		errs := ValidateStruct(&CreateScanRequest{
			ProjectID:   "550e8400-e29b-41d4-a716-446655440000",
			ScannerType: "semgrep",
		})
		assert.Nil(t, errs)
	})

	t.Run("invalid project id", func(t *testing.T) {
		errs := ValidateStruct(&CreateScanRequest{
			ProjectID:   "not-a-uuid",
			ScannerType: "semgrep",
		})
		assert.NotNil(t, errs)
	})

	t.Run("empty scanner type", func(t *testing.T) {
		errs := ValidateStruct(&CreateScanRequest{
			ProjectID: "550e8400-e29b-41d4-a716-446655440000",
		})
		assert.NotNil(t, errs)
	})
}

func TestValidateStruct_BulkUpdateFindingsRequest(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		errs := ValidateStruct(&BulkUpdateFindingsRequest{
			IDs:    []string{"550e8400-e29b-41d4-a716-446655440000"},
			Status: "fixed",
		})
		assert.Nil(t, errs)
	})

	t.Run("empty IDs", func(t *testing.T) {
		errs := ValidateStruct(&BulkUpdateFindingsRequest{
			IDs:    []string{},
			Status: "fixed",
		})
		assert.NotNil(t, errs)
	})

	t.Run("non-uuid in IDs", func(t *testing.T) {
		errs := ValidateStruct(&BulkUpdateFindingsRequest{
			IDs:    []string{"not-a-uuid"},
			Status: "fixed",
		})
		assert.NotNil(t, errs)
	})

	t.Run("invalid status", func(t *testing.T) {
		errs := ValidateStruct(&BulkUpdateFindingsRequest{
			IDs:    []string{"550e8400-e29b-41d4-a716-446655440000"},
			Status: "bogus",
		})
		assert.NotNil(t, errs)
	})
}

func TestValidateStruct_NilInput(t *testing.T) {
	// ValidateStruct(nil) panics — nil is not a valid input
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic for nil input")
		}
	}()
	ValidateStruct(nil)
}
