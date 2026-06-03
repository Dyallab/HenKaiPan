package middleware

import (
	"net/http/httptest"
	"testing"

	"aspm/internal/assert"
)

func TestHasCapability(t *testing.T) {
	tests := []struct {
		name string
		role string
		cap  string
		want bool
	}{
		{"admin_read", "admin", "read", true},
		{"admin_write", "admin", "write", true},
		{"viewer_read", "viewer", "read", true},
		{"viewer_write", "viewer", "write", false},
		{"unknown_role_read", "superadmin", "read", false},
		{"unknown_role_write", "superadmin", "write", false},
		{"empty_role_read", "", "read", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hasCapability(tt.role, tt.cap)
			assert.Equal(t, got, tt.want)
		})
	}
}

func TestExtractResourceID(t *testing.T) {
	tests := []struct {
		name         string
		path         string
		resourceType string
		want         string
	}{
		{"project_id", "/api/projects/123", "project", "123"},
		{"app_id", "/api/apps/abc", "app", "abc"},
		{"scan_id", "/api/scans/s-1", "scan", "s-1"},
		{"finding_id", "/api/findings/f-uuid", "finding", "f-uuid"},
		{"risk_acceptance_id", "/api/risk-acceptances/ra-1", "risk-acceptance", "ra-1"},
		{"no_match", "/api/projects", "finding", ""},
		{"no_id_after_type", "/api/risk-acceptances", "risk-acceptance", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", tt.path, nil)
			got := extractResourceID(req, tt.resourceType)
			assert.Equal(t, got, tt.want)
		})
	}
}
