package scanner

import (
	"os"
	"path/filepath"
	"testing"

	"aspm/internal/assert"
)

func readTestdata(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read testdata/%s: %v", name, err)
	}
	return data
}

// ── ParseSARIF ────────────────────────────────────────────────────────────

func TestParseSARIF_Semgrep(t *testing.T) {
	data := readTestdata(t, "semgrep.sarif.json")
	rows, err := ParseSARIF(data)
	assert.NoError(t, err)
	assert.Equal(t, 4, len(rows))

	// First finding: axios CSRF
	r0 := rows[0]
	t.Logf("r0 Severity=%q FilePath=%q CWEID=%q", r0.Severity, r0.FilePath, r0.CWEID)
	assert.Equal(t, "rules-react.security.audit.axios-csrf", r0.RuleID)
	assert.Equal(t, "Potential CSRF vulnerability via axios", r0.Title)
	assert.Equal(t, "high", r0.Severity) // CVSS 7.5 overrides warning→medium
	assert.Equal(t, "/components/LoginForm.jsx", r0.FilePath)
	assert.Equal(t, 42, r0.LineStart)
	assert.Equal(t, 42, r0.LineEnd)
	assert.Equal(t, "axios.post('/api/login', data)", r0.CodeSnippet)
	assert.Equal(t, "CWE-352", r0.CWEID) // from tags
	assert.NotEqual(t, "", r0.Description)

	// Second finding: XSS
	r1 := rows[1]
	t.Logf("r1 Severity=%q FilePath=%q CWEID=%q", r1.Severity, r1.FilePath, r1.CWEID)
	assert.Equal(t, "rules-python.flask.security.xss.xss-vulnerability", r1.RuleID)
	assert.Equal(t, "Flask XSS vulnerability", r1.Title)
	assert.Equal(t, "high", r1.Severity) // SARIF "error" → high
	assert.Equal(t, "/templates/user.html", r1.FilePath)
	assert.Equal(t, "CWE-79", r1.CWEID)  // from properties.cwe

	// Third finding: private key leak (empty shortDescription → RuleID as title)
	r2 := rows[2]
	t.Logf("r2 Severity=%q FilePath=%q", r2.Severity, r2.FilePath)
	assert.Equal(t, "rules-generic.generic.security.private-key-leak", r2.RuleID)
	assert.Equal(t, r2.RuleID, r2.Title) // empty shortDesc → RuleID
	assert.Equal(t, "high", r2.Severity)  // SARIF "error" → high
	assert.Equal(t, "/config/keys.json", r2.FilePath)

	// Fourth finding: no locations, same rule as first → CVSS 7.5 overrides
	r3 := rows[3]
	t.Logf("r3 Severity=%q FilePath=%q", r3.Severity, r3.FilePath)
	assert.Equal(t, "rules-react.security.audit.axios-csrf", r3.RuleID)
	assert.Equal(t, "high", r3.Severity) // note → low, but CVSS 7.5 overrides
	assert.Equal(t, "", r3.FilePath)
}

func TestParseSARIF_Trivy(t *testing.T) {
	data := readTestdata(t, "trivy.sarif.json")
	rows, err := ParseSARIF(data)
	assert.NoError(t, err)
	assert.Equal(t, 3, len(rows))

	// First: runc CVE
	r0 := rows[0]
	assert.Equal(t, "CVE-2024-21626", r0.RuleID)
	assert.Equal(t, "CVE-2024-21626", r0.CVEID)
	assert.Equal(t, "critical", r0.Severity)    // trivy message says CRITICAL
	assert.Equal(t, "runc", r0.PkgName)
	assert.Equal(t, "1.1.11", r0.PkgVersion)
	assert.Equal(t, "CVE-2024-21626 in runc@1.1.11", r0.Title)
	assert.Equal(t, "/go.sum", r0.FilePath)

	// Second: redis CVE (fixed version matches installed → "Fixed in: 7.0.15" prefix)
	r1 := rows[1]
	assert.Equal(t, "CVE-2023-45857", r1.RuleID)
	assert.Equal(t, "CVE-2023-45857", r1.CVEID)
	assert.Equal(t, "medium", r1.Severity) // trivy says MEDIUM
	assert.Equal(t, "redis", r1.PkgName)
	assert.Equal(t, "7.0.15", r1.PkgVersion)

	// Third: xz CVE with "N/A" fixed version
	r2 := rows[2]
	assert.Equal(t, "CVE-2024-3094", r2.RuleID)
	assert.Equal(t, "critical", r2.Severity)
	assert.Equal(t, "5.6.0", r2.PkgVersion) // "Installed Version" not "Fixed Version"
	assert.Equal(t, "", r2.FilePath)         // no locations
}

func TestParseSARIF_InvalidJSON(t *testing.T) {
	_, err := ParseSARIF([]byte("not json"))
	assert.NotNil(t, err)
	assert.True(t, len(err.Error()) > 0)
}

func TestParseSARIF_EmptyRuns(t *testing.T) {
	rows, err := ParseSARIF([]byte(`{"runs":[]}`))
	assert.NoError(t, err)
	assert.Equal(t, 0, len(rows))
}

// ── ParseGrype ────────────────────────────────────────────────────────────

func TestParseGrype(t *testing.T) {
	data := readTestdata(t, "grype.json")
	rows, err := ParseGrype(data)
	assert.NoError(t, err)
	assert.Equal(t, 3, len(rows))

	// First: runc CVE
	r0 := rows[0]
	assert.Equal(t, "CVE-2024-21626", r0.RuleID)
	assert.Equal(t, "CVE-2024-21626", r0.CVEID)
	assert.Equal(t, "critical", r0.Severity)
	assert.Equal(t, "runc", r0.PkgName)
	assert.Equal(t, "1.1.11", r0.PkgVersion)
	assert.Equal(t, "CVE-2024-21626 in runc@1.1.11", r0.Title)
	assert.Equal(t, "/go.sum", r0.FilePath)

	// Second: GHSA → CVE from relatedVulnerabilities
	r1 := rows[1]
	assert.Equal(t, "GHSA-xxxx-xxxx-xxxx", r1.RuleID)
	assert.Equal(t, "CVE-2024-12345", r1.CVEID) // from relatedVulnerabilities
	assert.Equal(t, "high", r1.Severity)
	assert.Equal(t, "lodash", r1.PkgName)
	assert.Equal(t, "", r1.FilePath) // no locations

	// Third: medium severity
	r2 := rows[2]
	assert.Equal(t, "CVE-2023-44487", r2.RuleID)
	assert.Equal(t, "medium", r2.Severity)
}

func TestParseGrype_Empty(t *testing.T) {
	rows, err := ParseGrype([]byte(`{"matches":[]}`))
	assert.NoError(t, err)
	assert.Equal(t, 0, len(rows))
}

func TestParseGrype_Invalid(t *testing.T) {
	_, err := ParseGrype([]byte("invalid"))
	assert.NotNil(t, err)
}

// ── ParseOSV ──────────────────────────────────────────────────────────────

func TestParseOSV(t *testing.T) {
	data := readTestdata(t, "osv.json")
	rows, err := ParseOSV(data)
	assert.NoError(t, err)
	assert.Equal(t, 2, len(rows))

	// First: CVE in golang.org/x/net
	r0 := rows[0]
	assert.Equal(t, "CVE-2023-44487", r0.RuleID)
	assert.Equal(t, "CVE-2023-44487", r0.CVEID)
	assert.Equal(t, "CWE-400", r0.CWEID)
	assert.Equal(t, "high", r0.Severity)
	assert.Equal(t, "golang.org/x/net", r0.PkgName)
	assert.Equal(t, "v0.12.0", r0.PkgVersion)
	assert.Equal(t, "/go.mod", r0.FilePath)
	assert.Equal(t, "CVE-2023-44487 in golang.org/x/net@v0.12.0", r0.Title)

	// Second: GHSA with CVE alias, empty summary → RuleID as title fallback
	r1 := rows[1]
	assert.Equal(t, "GHSA-xxxx-xxxx-xxxx", r1.RuleID)
	assert.Equal(t, "CVE-2024-12345", r1.CVEID) // from aliases
	assert.Equal(t, "high", r1.Severity)
	assert.Equal(t, "GHSA-xxxx-xxxx-xxxx in lodash@4.17.20", r1.Title)
}

func TestParseOSV_Empty(t *testing.T) {
	rows, err := ParseOSV([]byte(`{"results":[]}`))
	assert.NoError(t, err)
	assert.Equal(t, 0, len(rows))
}

func TestParseOSV_Invalid(t *testing.T) {
	_, err := ParseOSV([]byte("bad"))
	assert.NotNil(t, err)
}

// ── ParseTrufflehog ───────────────────────────────────────────────────────

func TestParseTrufflehog(t *testing.T) {
	data := readTestdata(t, "trufflehog.jsonl")
	rows, err := ParseTrufflehog(data)
	assert.NoError(t, err)
	assert.Equal(t, 3, len(rows))

	// First: verified Stripe key → critical
	r0 := rows[0]
	assert.Equal(t, "Stripe", r0.RuleID)
	assert.Equal(t, "Stripe secret detected", r0.Title)
	assert.Equal(t, "critical", r0.Severity) // verified → critical
	assert.Equal(t, "/config/credentials.js", r0.FilePath)
	assert.Equal(t, 15, r0.LineStart)
	assert.NotEqual(t, "", r0.SecretHash) // SHA256 of Raw

	// Second: unverified AWS key → high
	r1 := rows[1]
	assert.Equal(t, "AWS", r1.RuleID)
	assert.Equal(t, "high", r1.Severity) // unverified → high
	assert.Equal(t, 42, r1.LineStart)
	assert.NotEqual(t, "", r1.SecretHash)

	// Third: PrivateKey
	r2 := rows[2]
	assert.Equal(t, "PrivateKey", r2.RuleID)
	assert.Equal(t, "high", r2.Severity)
	assert.Equal(t, 1, r2.LineStart)
}

func TestParseTrufflehog_EmptyInput(t *testing.T) {
	rows, err := ParseTrufflehog([]byte{})
	assert.NoError(t, err)
	assert.Equal(t, 0, len(rows))
}

func TestParseTrufflehog_SkipInvalidLines(t *testing.T) {
	data := []byte("not json\n{\"DetectorName\":\"Valid\",\"Raw\":\"abc\",\"Verified\":false}")
	rows, err := ParseTrufflehog(data)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(rows))
	assert.Equal(t, "Valid", rows[0].RuleID)
}

// ── ParseGitleaks ─────────────────────────────────────────────────────────

func TestParseGitleaks(t *testing.T) {
	data := readTestdata(t, "gitleaks.json")
	rows, err := ParseGitleaks(data)
	assert.NoError(t, err)
	assert.Equal(t, 2, len(rows))

	// First
	r0 := rows[0]
	assert.Equal(t, "aws-access-key-id", r0.RuleID)
	assert.Equal(t, "AWS Access Key ID detected", r0.Title)
	assert.Equal(t, "high", r0.Severity)
	assert.Equal(t, "/config/aws.env", r0.FilePath)
	assert.Equal(t, 10, r0.LineStart)
	assert.Equal(t, 10, r0.LineEnd)
	assert.NotEqual(t, "", r0.SecretHash)

	// Second
	r1 := rows[1]
	assert.Equal(t, "github-pat", r1.RuleID)
	assert.Equal(t, 25, r1.LineStart)
}

func TestParseGitleaks_EmptyArray(t *testing.T) {
	rows, err := ParseGitleaks([]byte(`[]`))
	assert.NoError(t, err)
	assert.Equal(t, 0, len(rows))
}

func TestParseGitleaks_Null(t *testing.T) {
	rows, err := ParseGitleaks([]byte(`null`))
	assert.NoError(t, err)
	assert.Equal(t, 0, len(rows)) // returns nil, nil → empty
}

// ── ParseCheckov ──────────────────────────────────────────────────────────

func TestParseCheckov(t *testing.T) {
	data := readTestdata(t, "checkov.json")
	rows, err := ParseCheckov(data)
	assert.NoError(t, err)
	assert.Equal(t, 3, len(rows))

	// First: high severity
	r0 := rows[0]
	assert.Equal(t, "CKV_AWS_123", r0.RuleID)
	assert.Equal(t, "S3 bucket has public ACL", r0.Title)
	assert.Equal(t, "high", r0.Severity)
	assert.Equal(t, "/terraform/main.tf", r0.FilePath)
	assert.Equal(t, 10, r0.LineStart)
	assert.Equal(t, 20, r0.LineEnd)

	// Second: medium, Dockerfile
	r1 := rows[1]
	assert.Equal(t, "CKV_DOCKER_1", r1.RuleID)
	assert.Equal(t, "medium", r1.Severity)

	// Third: low, empty check name → RuleID as title
	r2 := rows[2]
	assert.Equal(t, "CKV_K8S_456", r2.RuleID)
	assert.Equal(t, "low", r2.Severity)
	assert.Equal(t, "CKV_K8S_456", r2.Title) // empty name → RuleID fallback
}

func TestParseCheckov_Invalid(t *testing.T) {
	_, err := ParseCheckov([]byte("not json"))
	assert.NotNil(t, err)
}

func TestParseCheckov_EmptyJSON(t *testing.T) {
	rows, err := ParseCheckov([]byte(`{"results":{"failed_checks":[]}}`))
	assert.NoError(t, err)
	assert.Equal(t, 0, len(rows))
}

// ── ParseKICS ─────────────────────────────────────────────────────────────

func TestParseKICS(t *testing.T) {
	data := readTestdata(t, "kics.json")
	rows, err := ParseKICS(data)
	assert.NoError(t, err)
	assert.Equal(t, 3, len(rows))

	// First query: 2 files
	r0 := rows[0]
	assert.Equal(t, "b1c4d5e6-f7a8-9012-3456-789abcdef012", r0.RuleID)
	assert.Equal(t, "S3 Bucket With All Protocols Enabled", r0.Title)
	assert.Equal(t, "high", r0.Severity)
	assert.Equal(t, "/terraform/s3.tf", r0.FilePath)
	assert.Equal(t, 15, r0.LineStart)

	r1 := rows[1]
	assert.Equal(t, 42, r1.LineStart) // second file in same query

	// Second query: 1 file
	r2 := rows[2]
	assert.Equal(t, "a1b2c3d4-e5f6-7890-abcd-ef1234567890", r2.RuleID)
	assert.Equal(t, "medium", r2.Severity)
	assert.Equal(t, "/Dockerfile", r2.FilePath)
	assert.Equal(t, 3, r2.LineStart)
}

func TestParseKICS_Invalid(t *testing.T) {
	_, err := ParseKICS([]byte("bad"))
	assert.NotNil(t, err)
}

func TestParseKICS_EmptyQueries(t *testing.T) {
	rows, err := ParseKICS([]byte(`{"queries":[]}`))
	assert.NoError(t, err)
	assert.Equal(t, 0, len(rows))
}

// ── ParseNuclei ───────────────────────────────────────────────────────────

func TestParseNuclei(t *testing.T) {
	data := readTestdata(t, "nuclei.jsonl")
	rows, err := ParseNuclei(data)
	assert.NoError(t, err)
	assert.Equal(t, 2, len(rows))

	// First: CVE finding
	r0 := rows[0]
	assert.Equal(t, "CVE-2024-21626", r0.RuleID)
	assert.Equal(t, "runc container breakout", r0.Title)
	assert.Equal(t, "critical", r0.Severity)
	assert.Equal(t, "CVE-2024-21626", r0.CVEID)
	assert.Equal(t, "CWE-403", r0.CWEID)
	assert.Equal(t, "https://example.com:8080", r0.FilePath)

	// Second: generic finding without CVE
	r1 := rows[1]
	assert.Equal(t, "http-missing-security-headers", r1.RuleID)
	assert.Equal(t, "Missing security headers", r1.Title)
	assert.Equal(t, "medium", r1.Severity)
	assert.Equal(t, "", r1.CVEID) // no cve-id
	assert.Equal(t, "CWE-693", r1.CWEID)
}

func TestParseNuclei_EmptyInput(t *testing.T) {
	rows, err := ParseNuclei([]byte{})
	assert.NoError(t, err)
	assert.Equal(t, 0, len(rows))
}
