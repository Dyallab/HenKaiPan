//go:build integration

package repository

// TDD (issue: vulnerability lifecycle): repository round-trip for the
// canonical vulnerability entity.
//
// Flow: upsert vuln → List → GetAffectedFindings → engine summary →
// UpdateStatus → link findings back (UpdateFindingVulnID → GetByID) →
// dedup on (project_id, vuln_uid) → nullable confidence_score.
//
// Requires a real Postgres (TEST_DATABASE_URL or DATABASE_URL); skips
// otherwise. Each test Connect + Reset for a clean slate.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"aspm/internal/assert"
	"aspm/internal/datascope"
	"aspm/internal/models"
	"aspm/internal/testdb"
	"aspm/internal/vulnerability"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func vulnTestStores(t *testing.T) (*pgxpool.Pool, Stores) {
	t.Helper()
	pool := testdb.Connect(t)
	testdb.Reset(t, pool)
	return pool, NewPostgresStores(pool, "")
}

func vulnTestProject(t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()
	var id string
	err := pool.QueryRow(context.Background(),
		`INSERT INTO projects (name) VALUES ($1) RETURNING id`,
		"vuln-test-"+time.Now().Format("150405.000000000")).Scan(&id)
	if err != nil {
		t.Fatalf("create test project: %v", err)
	}
	return id
}

func vulnTestScan(t *testing.T, stores Stores, projectID, scannerName string) string {
	t.Helper()
	id, err := stores.Scans.Insert(context.Background(),
		"https://example.com/repo.git", scannerName, uuid.NewString(), &projectID)
	if err != nil {
		t.Fatalf("insert scan: %v", err)
	}
	return id
}

func vulnTestFinding(t *testing.T, stores Stores, scanID, projectID string, f FindingInsert) string {
	t.Helper()
	f.ScanID = scanID
	f.ProjectID = projectID
	if f.Fingerprint == "" {
		f.Fingerprint = "fp-" + scanID + "-" + f.RuleID
	}
	id, err := stores.Findings.Insert(context.Background(), f)
	if err != nil {
		t.Fatalf("insert finding: %v", err)
	}
	if id == "" {
		t.Fatalf("insert finding returned empty id (fingerprint conflict)")
	}
	return id
}

// TestVulnerabilities_UIDAlgorithm locks the vuln_uid computation to the
// documented per-engine payloads: sast rule:path, sca rule, secret hash,
// iac rule:path — and verifies the stored row round-trips the same UID.
func TestVulnerabilities_UIDAlgorithm(t *testing.T) {
	ctx := context.Background()
	pool, stores := vulnTestStores(t)
	projectID := vulnTestProject(t, pool)

	cases := []struct {
		name        string
		engine      models.EngineType
		ruleID      string
		secretHash  string
		filePath    string
		scannerName string
		payload     string // raw bytes hashed into vuln_uid
	}{
		{"sast rule:path", models.EngineSAST, "semgrep-rule-1", "", "src/app.go", "semgrep", "sast:semgrep-rule-1:/app.go"},
		{"sca rule", models.EngineSCA, "GHSA-xxxx", "", "", "trivy", "sca:GHSA-xxxx"},
		{"secret hash", models.EngineSecrets, "", "abc123hash", "", "gitleaks", "secret:abc123hash"},
		{"iac rule:path", models.EngineIaC, "tfsec-rule", "", "main.tf", "tfsec", "iac:tfsec-rule:/main.tf"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			uid := vulnerability.ComputeVulnUID(tc.engine, tc.ruleID, "", "", "", tc.secretHash, tc.filePath)
			h := sha256.New()
			fmt.Fprint(h, tc.payload)
			assert.Equal(t, uid, hex.EncodeToString(h.Sum(nil)))

			_, err := stores.Vulnerabilities.Upsert(ctx, VulnerabilityUpsert{
				VulnUID:     uid,
				ProjectID:   projectID,
				Title:       "uid-algo-" + tc.name,
				Severity:    models.SeverityHigh,
				EngineType:  string(tc.engine),
				RuleID:      tc.ruleID,
				SecretHash:  tc.secretHash,
				FilePath:    vulnerability.NormalizePath(tc.filePath),
				ScannerName: tc.scannerName,
			})
			assert.NoError(t, err)

			got, err := stores.Vulnerabilities.GetByUID(ctx, projectID, uid)
			assert.NoError(t, err)
			assert.Equal(t, got.VulnUID, uid)
			assert.Equal(t, got.EngineType, tc.engine)
		})
	}
}

// TestVulnerabilities_CreateAndList covers upsert defaults (status open,
// finding_count 1, scanner_coverage seeded, confidence NULL) and the
// List round-trip with project + search filters.
func TestVulnerabilities_CreateAndList(t *testing.T) {
	ctx := context.Background()
	pool, stores := vulnTestStores(t)
	projectID := vulnTestProject(t, pool)

	uid := vulnerability.ComputeVulnUID(models.EngineSAST, "semgrep-rule-1", "", "", "", "", "src/app.go")
	assert.NotEqual(t, uid, "")

	vuln, err := stores.Vulnerabilities.Upsert(ctx, VulnerabilityUpsert{
		VulnUID:     uid,
		ProjectID:   projectID,
		Title:       "SQL injection in app.go",
		Description: "User input reaches a raw query",
		Severity:    models.SeverityHigh,
		EngineType:  string(models.EngineSAST),
		RuleID:      "semgrep-rule-1",
		FilePath:    "/src/app.go",
		ScannerName: "semgrep",
	})
	assert.NoError(t, err)
	assert.NotNil(t, vuln)
	assert.Equal(t, vuln.Status, "open") // column default
	assert.Equal(t, vuln.FindingCount, 1) // column default
	assert.Equal(t, vuln.ScannerCoverage, []string{"semgrep"})
	assert.Nil(t, vuln.ConfidenceScore) // nullable, NULL until recalc

	// List back by project.
	rows, total, err := stores.Vulnerabilities.List(ctx, VulnerabilityFilter{ProjectID: projectID, Page: 1, Limit: 10})
	assert.NoError(t, err)
	assert.Equal(t, total, 1)
	assert.Equal(t, len(rows), 1)
	assert.Equal(t, rows[0].ID, vuln.ID)
	assert.Equal(t, rows[0].VulnUID, uid)
	assert.Equal(t, rows[0].Title, "SQL injection in app.go")
	assert.Equal(t, rows[0].Severity, models.SeverityHigh)
	assert.Equal(t, rows[0].EngineType, models.EngineSAST)

	// Search filter.
	rows, total, err = stores.Vulnerabilities.List(ctx, VulnerabilityFilter{ProjectID: projectID, Search: "SQL injection", Page: 1, Limit: 10})
	assert.NoError(t, err)
	assert.Equal(t, total, 1)
	assert.Equal(t, len(rows), 1)

	// Unrelated project sees nothing.
	otherProject := vulnTestProject(t, pool)
	rows, total, err = stores.Vulnerabilities.List(ctx, VulnerabilityFilter{ProjectID: otherProject, Page: 1, Limit: 10})
	assert.NoError(t, err)
	assert.Equal(t, total, 0)
	assert.Equal(t, len(rows), 0)
}

// TestVulnerabilities_GetAffectedFindings covers the findings→vulnerability
// link: empty before linking, populated after UpdateFindingVulnID, with
// project context joined in.
func TestVulnerabilities_GetAffectedFindings(t *testing.T) {
	ctx := context.Background()
	pool, stores := vulnTestStores(t)
	projectID := vulnTestProject(t, pool)
	scanID := vulnTestScan(t, stores, projectID, "semgrep")

	findingID := vulnTestFinding(t, stores, scanID, projectID, FindingInsert{
		Scanner:     "semgrep",
		RuleID:      "semgrep-rule-1",
		Title:       "SQL injection",
		Description: "raw query",
		Severity:    models.SeverityHigh,
		FilePath:    "src/app.go",
		LineStart:   10,
		LineEnd:     12,
		Fingerprint: "fp-affected",
	})

	uid := vulnerability.ComputeVulnUID(models.EngineSAST, "semgrep-rule-1", "", "", "", "", "src/app.go")
	vuln, err := stores.Vulnerabilities.Upsert(ctx, VulnerabilityUpsert{
		VulnUID:     uid,
		ProjectID:   projectID,
		Title:       "SQL injection in app.go",
		Severity:    models.SeverityHigh,
		EngineType:  string(models.EngineSAST),
		RuleID:      "semgrep-rule-1",
		FilePath:    "/src/app.go",
		ScannerName: "semgrep",
	})
	assert.NoError(t, err)

	// Before linking: no affected findings.
	affected, err := stores.Vulnerabilities.GetAffectedFindings(ctx, vuln.ID)
	assert.NoError(t, err)
	assert.Equal(t, len(affected), 0)

	// Link finding → vulnerability.
	assert.NoError(t, stores.Vulnerabilities.UpdateFindingVulnID(ctx, findingID, vuln.ID))

	affected, err = stores.Vulnerabilities.GetAffectedFindings(ctx, vuln.ID)
	assert.NoError(t, err)
	assert.Equal(t, len(affected), 1)
	assert.Equal(t, affected[0].ID, findingID)
	assert.Equal(t, affected[0].Scanner, "semgrep")
	assert.Equal(t, affected[0].ProjectID, projectID)
	assert.NotEqual(t, affected[0].ProjectName, "")
}

// TestVulnerabilities_EngineSummary covers GetProjectEngineSummaries
// aggregation: counts per engine, totals, and open-only counts after a
// status change.
func TestVulnerabilities_EngineSummary(t *testing.T) {
	ctx := context.Background()
	pool, stores := vulnTestStores(t)
	projectID := vulnTestProject(t, pool)

	upsert := func(uid, title, severity, engine, ruleID, scannerName string) {
		t.Helper()
		_, err := stores.Vulnerabilities.Upsert(ctx, VulnerabilityUpsert{
			VulnUID:     uid,
			ProjectID:   projectID,
			Title:       title,
			Severity:    severity,
			EngineType:  engine,
			RuleID:      ruleID,
			FilePath:    "/src/app.go",
			ScannerName: scannerName,
		})
		assert.NoError(t, err)
	}

	sastUID1 := vulnerability.ComputeVulnUID(models.EngineSAST, "semgrep-rule-1", "", "", "", "", "src/app.go")
	upsert(sastUID1, "SQLi", models.SeverityHigh, string(models.EngineSAST), "semgrep-rule-1", "semgrep")

	scaUID := vulnerability.ComputeVulnUID(models.EngineSCA, "GHSA-xxxx", "", "", "", "", "")
	upsert(scaUID, "lodash vuln", models.SeverityCritical, string(models.EngineSCA), "GHSA-xxxx", "trivy")

	sastUID2 := vulnerability.ComputeVulnUID(models.EngineSAST, "semgrep-rule-2", "", "", "", "", "src/app.go")
	upsert(sastUID2, "XSS", models.SeverityMedium, string(models.EngineSAST), "semgrep-rule-2", "semgrep")

	// Mark one sast vuln fixed → open count drops.
	v2, err := stores.Vulnerabilities.GetByUID(ctx, projectID, sastUID2)
	assert.NoError(t, err)
	assert.NoError(t, stores.Vulnerabilities.UpdateStatus(ctx, v2.ID, "fixed"))

	summaries, err := stores.Vulnerabilities.GetProjectEngineSummaries(ctx, datascope.Admin())
	assert.NoError(t, err)
	assert.Equal(t, len(summaries), 1)
	s := summaries[0]
	assert.Equal(t, s.ProjectID, projectID)
	assert.Equal(t, s.TotalVulns, 3)
	assert.Equal(t, s.TotalOpen, 2)
	assert.Equal(t, s.ByEngine["sast"], 2)
	assert.Equal(t, s.ByEngine["sca"], 1)
}

// TestVulnerabilities_UpdateStatus covers the status transition and its
// effect on List filters (OnlyOpen excludes resolved, Status filter finds).
func TestVulnerabilities_UpdateStatus(t *testing.T) {
	ctx := context.Background()
	pool, stores := vulnTestStores(t)
	projectID := vulnTestProject(t, pool)

	uid := vulnerability.ComputeVulnUID(models.EngineSAST, "semgrep-rule-1", "", "", "", "", "src/app.go")
	vuln, err := stores.Vulnerabilities.Upsert(ctx, VulnerabilityUpsert{
		VulnUID:     uid,
		ProjectID:   projectID,
		Title:       "SQL injection",
		Severity:    models.SeverityHigh,
		EngineType:  string(models.EngineSAST),
		RuleID:      "semgrep-rule-1",
		FilePath:    "/src/app.go",
		ScannerName: "semgrep",
	})
	assert.NoError(t, err)
	assert.Equal(t, vuln.Status, "open")

	assert.NoError(t, stores.Vulnerabilities.UpdateStatus(ctx, vuln.ID, "fixed"))

	got, err := stores.Vulnerabilities.GetByID(ctx, vuln.ID)
	assert.NoError(t, err)
	assert.Equal(t, got.Status, "fixed")

	// OnlyOpen excludes resolved vulns.
	rows, total, err := stores.Vulnerabilities.List(ctx, VulnerabilityFilter{ProjectID: projectID, OnlyOpen: true, Page: 1, Limit: 10})
	assert.NoError(t, err)
	assert.Equal(t, total, 0)
	assert.Equal(t, len(rows), 0)

	// Status filter finds it.
	rows, total, err = stores.Vulnerabilities.List(ctx, VulnerabilityFilter{ProjectID: projectID, Status: "fixed", Page: 1, Limit: 10})
	assert.NoError(t, err)
	assert.Equal(t, total, 1)
	assert.Equal(t, rows[0].ID, vuln.ID)
}

// TestVulnerabilities_LinkBack covers the finding side of the link:
// UPDATE findings.vulnerability_id → Findings.GetByID returns it.
func TestVulnerabilities_LinkBack(t *testing.T) {
	ctx := context.Background()
	pool, stores := vulnTestStores(t)
	projectID := vulnTestProject(t, pool)
	scanID := vulnTestScan(t, stores, projectID, "semgrep")

	findingID := vulnTestFinding(t, stores, scanID, projectID, FindingInsert{
		Scanner:     "semgrep",
		RuleID:      "semgrep-rule-1",
		Title:       "SQL injection",
		Severity:    models.SeverityHigh,
		FilePath:    "src/app.go",
		Fingerprint: "fp-linkback",
	})

	uid := vulnerability.ComputeVulnUID(models.EngineSAST, "semgrep-rule-1", "", "", "", "", "src/app.go")
	vuln, err := stores.Vulnerabilities.Upsert(ctx, VulnerabilityUpsert{
		VulnUID:     uid,
		ProjectID:   projectID,
		Title:       "SQL injection",
		Severity:    models.SeverityHigh,
		EngineType:  string(models.EngineSAST),
		RuleID:      "semgrep-rule-1",
		FilePath:    "/src/app.go",
		ScannerName: "semgrep",
	})
	assert.NoError(t, err)

	// Before link: finding has no vulnerability_id.
	f, err := stores.Findings.GetByID(ctx, findingID)
	assert.NoError(t, err)
	assert.Nil(t, f.VulnerabilityID)

	assert.NoError(t, stores.Vulnerabilities.UpdateFindingVulnID(ctx, findingID, vuln.ID))

	f, err = stores.Findings.GetByID(ctx, findingID)
	assert.NoError(t, err)
	assert.NotNil(t, f.VulnerabilityID)
	assert.Equal(t, *f.VulnerabilityID, vuln.ID)
}

// TestVulnerabilities_Deduplicate covers the UNIQUE (project_id, vuln_uid)
// constraint: a second upsert with the same UID updates the same row
// (finding_count increments, scanner_coverage merges) instead of inserting.
func TestVulnerabilities_Deduplicate(t *testing.T) {
	ctx := context.Background()
	pool, stores := vulnTestStores(t)
	projectID := vulnTestProject(t, pool)

	uid := vulnerability.ComputeVulnUID(models.EngineSAST, "semgrep-rule-1", "", "", "", "", "src/app.go")

	first, err := stores.Vulnerabilities.Upsert(ctx, VulnerabilityUpsert{
		VulnUID:     uid,
		ProjectID:   projectID,
		Title:       "SQL injection",
		Severity:    models.SeverityHigh,
		EngineType:  string(models.EngineSAST),
		RuleID:      "semgrep-rule-1",
		FilePath:    "/src/app.go",
		ScannerName: "semgrep",
	})
	assert.NoError(t, err)

	// Same (project_id, vuln_uid) from a later scan batch → same row.
	second, err := stores.Vulnerabilities.Upsert(ctx, VulnerabilityUpsert{
		VulnUID:     uid,
		ProjectID:   projectID,
		Title:       "SQL injection (updated title)",
		Severity:    models.SeverityHigh,
		EngineType:  string(models.EngineSAST),
		RuleID:      "semgrep-rule-1",
		FilePath:    "/src/app.go",
		ScannerName: "semgrep",
	})
	assert.NoError(t, err)
	assert.Equal(t, second.ID, first.ID)
	assert.Equal(t, second.FindingCount, 2) // incremented, not a new row

	// Exactly one row in the DB.
	var count int
	err = pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM vulnerabilities WHERE project_id = $1 AND vuln_uid = $2`,
		projectID, uid).Scan(&count)
	assert.NoError(t, err)
	assert.Equal(t, count, 1)

	// A second scanner reporting the same vuln merges into scanner_coverage.
	third, err := stores.Vulnerabilities.Upsert(ctx, VulnerabilityUpsert{
		VulnUID:     uid,
		ProjectID:   projectID,
		Title:       "SQL injection",
		Severity:    models.SeverityHigh,
		EngineType:  string(models.EngineSAST),
		RuleID:      "semgrep-rule-1",
		FilePath:    "/src/app.go",
		ScannerName: "codeql",
	})
	assert.NoError(t, err)
	assert.Equal(t, third.ID, first.ID)
	assert.Equal(t, third.FindingCount, 3)
	assert.Equal(t, len(third.ScannerCoverage), 2)
	seen := map[string]bool{}
	for _, s := range third.ScannerCoverage {
		seen[s] = true
	}
	assert.True(t, seen["semgrep"])
	assert.True(t, seen["codeql"])
}

// TestVulnerabilities_ConfidenceNullable covers confidence_score being NULL
// after upsert and populated by RecalcConfidence once findings are linked.
func TestVulnerabilities_ConfidenceNullable(t *testing.T) {
	ctx := context.Background()
	pool, stores := vulnTestStores(t)
	projectID := vulnTestProject(t, pool)

	uid := vulnerability.ComputeVulnUID(models.EngineSAST, "semgrep-rule-1", "", "", "", "", "src/app.go")
	vuln, err := stores.Vulnerabilities.Upsert(ctx, VulnerabilityUpsert{
		VulnUID:     uid,
		ProjectID:   projectID,
		Title:       "SQL injection",
		Severity:    models.SeverityHigh,
		EngineType:  string(models.EngineSAST),
		RuleID:      "semgrep-rule-1",
		FilePath:    "/src/app.go",
		ScannerName: "semgrep",
	})
	assert.NoError(t, err)
	assert.Nil(t, vuln.ConfidenceScore)

	// Raw DB check: column is NULL.
	var score *float64
	err = pool.QueryRow(ctx, `SELECT confidence_score FROM vulnerabilities WHERE id = $1`, vuln.ID).Scan(&score)
	assert.NoError(t, err)
	assert.Nil(t, score)

	// Link one finding and recalc → single scanner → 0.5.
	scanID := vulnTestScan(t, stores, projectID, "semgrep")
	findingID := vulnTestFinding(t, stores, scanID, projectID, FindingInsert{
		Scanner:     "semgrep",
		RuleID:      "semgrep-rule-1",
		Title:       "SQL injection",
		Severity:    models.SeverityHigh,
		FilePath:    "src/app.go",
		Fingerprint: "fp-confidence",
	})
	assert.NoError(t, stores.Vulnerabilities.UpdateFindingVulnID(ctx, findingID, vuln.ID))
	assert.NoError(t, stores.Vulnerabilities.RecalcConfidence(ctx, vuln.ID))

	got, err := stores.Vulnerabilities.GetByID(ctx, vuln.ID)
	assert.NoError(t, err)
	assert.NotNil(t, got.ConfidenceScore)
	assert.Equal(t, *got.ConfidenceScore, 0.5)
}