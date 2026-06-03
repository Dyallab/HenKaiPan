package scanner

import (
	"testing"

	"aspm/internal/assert"
)

func TestGet_Existing(t *testing.T) {
	tests := []struct {
		name     string
		scanner  string
		wantCat  Category
		wantDesc string
	}{
		{"semgrep", "semgrep", CategorySAST, "Static analysis for 30+ languages"},
		{"trivy", "trivy", CategorySCA, "Vulnerability scanner for packages and containers"},
		{"gitleaks", "gitleaks", CategorySecrets, "Detect hardcoded secrets in git repos"},
		{"checkov", "checkov", CategoryIaC, "IaC security analysis (Terraform, K8s, Dockerfile, ARM…)"},
		{"trivy-image", "trivy-image", CategoryContainers, "Container image vulnerability scanner — target: image ref (e.g. nginx:latest)"},
		{"nuclei", "nuclei", CategoryDAST, "Template-based web vulnerability scanner — target: web URL"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, ok := Get(tt.scanner)
			assert.True(t, ok)
			assert.Equal(t, tt.scanner, s.Name)
			assert.Equal(t, tt.wantCat, s.Category)
			assert.Equal(t, tt.wantDesc, s.Description)
		})
	}
}

func TestGet_NonExistent(t *testing.T) {
	_, ok := Get("nonexistent")
	assert.False(t, ok)
}

func TestCategoryFor_AllCategories(t *testing.T) {
	tests := []struct {
		name    string
		scanner string
		wantCat Category
		wantOK  bool
	}{
		{"sast", "semgrep", CategorySAST, true},
		{"sca", "grype", CategorySCA, true},
		{"secrets", "trufflehog", CategorySecrets, true},
		{"iac", "tfsec", CategoryIaC, true},
		{"containers", "grype-image", CategoryContainers, true},
		{"dast", "nuclei", CategoryDAST, true},
		{"nonexistent", "unknown", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cat, ok := CategoryFor(tt.scanner)
			assert.Equal(t, tt.wantOK, ok)
			if tt.wantOK {
				assert.Equal(t, tt.wantCat, cat)
			}
		})
	}
}

func TestSameCategory(t *testing.T) {
	tests := []struct {
		name string
		a, b string
		want bool
	}{
		{"both sast", "semgrep", "gosec", true},
		{"both sca", "trivy", "grype", true},
		{"both secrets", "trufflehog", "gitleaks", true},
		{"both containers", "trivy-image", "grype-image", true},
		{"different categories", "semgrep", "trivy", false},
		{"one nonexistent", "semgrep", "unknown", false},
		{"both nonexistent", "unknown", "nope", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, SameCategory(tt.a, tt.b))
		})
	}
}

func TestListInfo_AllScanners(t *testing.T) {
	infos := ListInfo()
	assert.Equal(t, len(Registry), len(infos))

	// Verify all 13 scanners present
	names := make(map[string]bool)
	for _, info := range infos {
		names[info.Name] = true
		assert.NotEqual(t, "", info.Category)
		assert.NotEqual(t, "", info.Description)
		assert.NotEqual(t, "", info.TargetType)
	}

	for name := range Registry {
		if !names[name] {
			t.Errorf("scanner %s missing from ListInfo", name)
		}
	}
}

func TestResolvePack(t *testing.T) {
	tests := []struct {
		name  string
		id    string
		want  int
		wantOK bool
	}{
		{"sast", "sast", 2, true},
		{"sca", "sca", 3, true},
		{"secrets", "secrets", 2, true},
		{"iac", "iac", 3, true},
		{"containers", "containers", 2, true},
		{"unknown pack", "unknown", 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanners, ok := ResolvePack(tt.id)
			assert.Equal(t, tt.wantOK, ok)
			if ok {
				assert.Equal(t, tt.want, len(scanners))
				// Verify each scanner exists in Registry
				for _, s := range scanners {
					_, exists := Get(s)
					if !exists {
						t.Errorf("scanner %s in pack %s not found in Registry", s, tt.id)
					}
				}
			}
		})
	}
}

func TestResolvePack_All(t *testing.T) {
	scanners, ok := ResolvePack("all")
	assert.True(t, ok)
	// "all" pack = all git scanners
	expected := GitScannerNames()
	assert.Equal(t, len(expected), len(scanners))
}

func TestGitScannerNames_Sanity(t *testing.T) {
	names := GitScannerNames()
	if len(names) == 0 {
		t.Error("GitScannerNames returned empty list")
	}

	// Should include git-based scanners
	check := func(name string, expected bool) {
		if contains(names, name) != expected {
			t.Errorf("GitScannerNames contains %s = %v, want %v", name, !expected, expected)
		}
	}
	check("semgrep", true)
	check("trivy", true)
	check("gitleaks", true)
	check("trivy-image", false)
	check("grype-image", false)
	check("nuclei", false)
}

func TestNewExecutor_Binaries(t *testing.T) {
	e := NewExecutor()
	assert.NotNil(t, e)
	assert.NotNil(t, e.binaries)

	expectedBinaries := []string{
		"semgrep", "gosec", "trivy", "trivy-image",
		"grype", "grype-image", "osv-scanner",
		"trufflehog", "gitleaks", "checkov",
		"tfsec", "kics", "nuclei",
	}
	for _, name := range expectedBinaries {
		_, ok := e.binaries[name]
		if !ok {
			t.Errorf("binary mapping missing for %s", name)
		}
	}
}

func TestCheckBinaryAvailability_Unknown(t *testing.T) {
	_, err := CheckBinaryAvailability("nonexistent-scanner")
	assert.NotNil(t, err)
	assert.Equal(t, "unknown scanner: nonexistent-scanner", err.Error())
}

func TestCheckBinaryAvailability_Known(t *testing.T) {
	// On dev machine scanners likely aren't installed — should return "not found" error,
	// not "unknown scanner" error. Just verify it doesn't panic.
	_, err := CheckBinaryAvailability("semgrep")
	// If scanner IS found, path is non-empty. Otherwise it's "not found" error.
	if err != nil {
		assert.NotEqual(t, "unknown scanner: semgrep", err.Error())
	}
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
