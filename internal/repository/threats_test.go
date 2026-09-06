package repository

// TDD (issue #64): threats repository store round-trip.
// Flow: upsert deps → upsert advisories → insert hits → ListExposures
// with filters/pagination. Requires shared docker PG (localhost:5432).

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"aspm/internal/threats"

	"github.com/jackc/pgx/v5/pgxpool"
)

func threatsTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		dsn = "postgres://aspm:aspm@localhost:5432/aspm?sslmode=disable"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Skipf("test db unavailable, skipping: %v", err)
	}
	t.Cleanup(pool.Close)
	if err := pool.Ping(ctx); err != nil {
		t.Skipf("ping test db: %v", err)
	}
	return pool
}

func threatsTestProject(t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()
	var id string
	err := pool.QueryRow(context.Background(),
		`INSERT INTO projects (name) VALUES ($1) RETURNING id`,
		"threats-test-"+time.Now().Format("150405.000000000")).Scan(&id)
	if err != nil {
		t.Fatalf("create test project: %v", err)
	}
	t.Cleanup(func() {
		ctx := context.Background()
		_, _ = pool.Exec(ctx, `DELETE FROM project_inventory_hits WHERE project_id = $1`, id)
		_, _ = pool.Exec(ctx, `DELETE FROM project_dependencies WHERE project_id = $1`, id)
		_, _ = pool.Exec(ctx, `DELETE FROM projects WHERE id = $1`, id)
		_, _ = pool.Exec(ctx, `DELETE FROM threat_advisories WHERE advisory_id LIKE 'GHSA-TEST-%'`)
	})
	return id
}

func TestThreats_RoundTrip(t *testing.T) {
	ctx := context.Background()
	pool := threatsTestPool(t)
	projectID := threatsTestProject(t, pool)
	stores := NewPostgresStores(pool, "")

	deps := []threats.Dependency{
		{Ecosystem: "npm", Name: "lodash", Version: "4.17.20", SourceFile: "package.json"},
		{Ecosystem: "go", Name: "github.com/gin-gonic/gin", Version: "v1.9.0", SourceFile: "go.mod"},
	}
	if err := stores.Threats.UpsertDependencies(ctx, projectID, deps); err != nil {
		t.Fatalf("upsert dependencies: %v", err)
	}

	// Re-upsert same snapshot must be idempotent (no duplicate rows).
	if err := stores.Threats.UpsertDependencies(ctx, projectID, deps); err != nil {
		t.Fatalf("re-upsert dependencies: %v", err)
	}
	var depCount int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM project_dependencies WHERE project_id = $1`, projectID).Scan(&depCount); err != nil {
		t.Fatalf("count dependencies: %v", err)
	}
	if depCount != 2 {
		t.Fatalf("expected 2 dependencies after idempotent upsert, got %d", depCount)
	}

	advs := []threats.Advisory{
		{
			AdvisoryID: "GHSA-TEST-0001",
			Source:     "osv",
			CVEID:      "CVE-2021-23337",
			Severity:   "HIGH",
			Published:  time.Date(2021, 2, 1, 0, 0, 0, 0, time.UTC),
			AffectedPackages: []threats.AffectedPackage{
				{Ecosystem: "npm", Name: "lodash", Ranges: []threats.AffectedRange{
					{Type: "SEMVER", Events: []threats.RangeEvent{{Introduced: "0", Fixed: "4.17.21"}}},
				}},
			},
		},
		{
			AdvisoryID: "GHSA-TEST-0002",
			Source:     "osv",
			CVEID:      "CVE-2023-44487",
			Severity:   "CRITICAL",
			Published:  time.Date(2023, 10, 10, 0, 0, 0, 0, time.UTC),
			AffectedPackages: []threats.AffectedPackage{
				{Ecosystem: "Go", Name: "github.com/gin-gonic/gin"},
			},
		},
	}
	if err := stores.Threats.UpsertAdvisories(ctx, advs, nil); err != nil {
		t.Fatalf("upsert advisories: %v", err)
	}
	// Re-upsert with changed severity must update in place, not duplicate.
	advs[0].Severity = "CRITICAL"
	if err := stores.Threats.UpsertAdvisories(ctx, advs[:1], nil); err != nil {
		t.Fatalf("re-upsert advisory: %v", err)
	}
	var sev string
	if err := pool.QueryRow(ctx, `SELECT severity FROM threat_advisories WHERE advisory_id = $1`, "GHSA-TEST-0001").Scan(&sev); err != nil {
		t.Fatalf("read advisory severity: %v", err)
	}
	if sev != "critical" {
		t.Fatalf("expected advisory severity normalized to critical, got %q", sev)
	}

	hits := []ThreatHit{
		{AdvisoryID: "GHSA-TEST-0001", PkgName: "lodash", PkgVersion: "4.17.20", InventoryStatus: "declared", MatchStatus: "unconfirmed", Evidence: json.RawMessage(`{"declared":{"name":"lodash"}}`)},
		{AdvisoryID: "GHSA-TEST-0002", PkgName: "github.com/gin-gonic/gin", PkgVersion: "v1.9.0", InventoryStatus: "declared", MatchStatus: "active_threat", RuntimeStatus: "L1"},
	}
	if err := stores.Threats.InsertHits(ctx, projectID, hits); err != nil {
		t.Fatalf("insert hits: %v", err)
	}

	// Mark one advisory as KEV via overlay (ingest track owns the flag).
	if _, err := pool.Exec(ctx, `UPDATE threat_advisories SET kev = TRUE WHERE advisory_id = $1`, "GHSA-TEST-0002"); err != nil {
		t.Fatalf("set kev flag: %v", err)
	}

	// List all.
	rows, total, err := stores.Threats.ListExposures(ctx, ExposureFilter{ProjectID: projectID, Page: 1, Limit: 10})
	if err != nil {
		t.Fatalf("list exposures: %v", err)
	}
	if total != 2 || len(rows) != 2 {
		t.Fatalf("expected total=2 rows=2, got total=%d rows=%d", total, len(rows))
	}
	if rows[0].CVEID == "" || rows[0].Severity == "" {
		t.Fatalf("expected joined advisory columns (cve/severity), got %+v", rows[0])
	}
	foundEvidence := false
	for _, r := range rows {
		if r.AdvisoryID != "GHSA-TEST-0001" {
			continue
		}
		var ev map[string]any
		if err := json.Unmarshal(r.Evidence, &ev); err != nil {
			t.Fatalf("evidence is not JSON: %v", err)
		}
		if _, ok := ev["declared"]; !ok {
			t.Fatalf("evidence missing declared key: %s", r.Evidence)
		}
		foundEvidence = true
	}
	if !foundEvidence {
		t.Fatalf("expected GHSA-TEST-0001 row with evidence, got %+v", rows)
	}

	// KEVOnly filter.
	rows, total, err = stores.Threats.ListExposures(ctx, ExposureFilter{ProjectID: projectID, KEVOnly: true, Page: 1, Limit: 10})
	if err != nil {
		t.Fatalf("list kev exposures: %v", err)
	}
	if total != 1 || len(rows) != 1 || rows[0].AdvisoryID != "GHSA-TEST-0002" {
		t.Fatalf("expected 1 KEV exposure GHSA-TEST-0002, got total=%d rows=%+v", total, rows)
	}
	if !rows[0].KEV {
		t.Fatalf("expected KEV=true on kev-filtered row")
	}

	// MatchStatus filter.
	rows, total, err = stores.Threats.ListExposures(ctx, ExposureFilter{ProjectID: projectID, MatchStatus: "active_threat", Page: 1, Limit: 10})
	if err != nil {
		t.Fatalf("list by match status: %v", err)
	}
	if total != 1 || rows[0].MatchStatus != "active_threat" {
		t.Fatalf("expected 1 active_threat exposure, got total=%d rows=%+v", total, rows)
	}

	// InventoryStatus filter.
	rows, total, err = stores.Threats.ListExposures(ctx, ExposureFilter{ProjectID: projectID, InventoryStatus: "declared", Page: 1, Limit: 10})
	if err != nil {
		t.Fatalf("list by inventory status: %v", err)
	}
	if total != 2 {
		t.Fatalf("expected 2 declared exposures, got total=%d", total)
	}

	// Q search by CVE.
	rows, total, err = stores.Threats.ListExposures(ctx, ExposureFilter{ProjectID: projectID, Q: "CVE-2021-23337", Page: 1, Limit: 10})
	if err != nil {
		t.Fatalf("list by q: %v", err)
	}
	if total != 1 || rows[0].AdvisoryID != "GHSA-TEST-0001" {
		t.Fatalf("expected 1 row for CVE search, got total=%d rows=%+v", total, rows)
	}

	// Pagination: limit 1 → 2 total, 1 row per page.
	p1, total, err := stores.Threats.ListExposures(ctx, ExposureFilter{ProjectID: projectID, Page: 1, Limit: 1})
	if err != nil {
		t.Fatalf("list page 1: %v", err)
	}
	p2, _, err := stores.Threats.ListExposures(ctx, ExposureFilter{ProjectID: projectID, Page: 2, Limit: 1})
	if err != nil {
		t.Fatalf("list page 2: %v", err)
	}
	if total != 2 || len(p1) != 1 || len(p2) != 1 || p1[0].HitID == p2[0].HitID {
		t.Fatalf("expected 2 distinct pages, got total=%d p1=%+v p2=%+v", total, p1, p2)
	}

	// Empty ProjectID means all projects (admin cross-project listing, #64 E2E 500).
	rows, total, err = stores.Threats.ListExposures(ctx, ExposureFilter{Page: 1, Limit: 10})
	if err != nil {
		t.Fatalf("list without project filter: %v", err)
	}
	if total != 2 || len(rows) != 2 {
		t.Fatalf("expected total=2 rows=2 without project filter, got total=%d rows=%d", total, len(rows))
	}

	// Sort override must not break the query (whitelist).
	if _, _, err := stores.Threats.ListExposures(ctx, ExposureFilter{ProjectID: projectID, Page: 1, Limit: 10, Sort: "published_at"}); err != nil {
		t.Fatalf("list sorted: %v", err)
	}
	if _, _, err := stores.Threats.ListExposures(ctx, ExposureFilter{ProjectID: projectID, Page: 1, Limit: 10, Sort: "'; DROP TABLE projects; --"}); err != nil {
		t.Fatalf("list with hostile sort must fall back safely, got err: %v", err)
	}
}

func TestThreats_ReconcileHitsIdempotent(t *testing.T) {
	ctx := context.Background()
	pool := threatsTestPool(t)
	projectID := threatsTestProject(t, pool)
	stores := NewPostgresStores(pool, "")

	advs := []threats.Advisory{{
		AdvisoryID: "GHSA-TEST-RECON-1",
		Source:     "osv",
		CVEID:      "CVE-2024-0001",
		Severity:   "HIGH",
		AffectedPackages: []threats.AffectedPackage{
			{Ecosystem: "npm", Name: "lodash"},
		},
	}}
	if err := stores.Threats.UpsertAdvisories(ctx, advs, nil); err != nil {
		t.Fatalf("upsert advisories: %v", err)
	}

	hit := ThreatHit{
		AdvisoryID: "GHSA-TEST-RECON-1", PkgName: "lodash", PkgVersion: "4.17.20",
		InventoryStatus: "declared", MatchStatus: "unconfirmed",
		Evidence:        json.RawMessage(`{"declared":{"name":"lodash"}}`),
	}

	// First sync inserts and reports the hit as new.
	fresh, err := stores.Threats.ReconcileHits(ctx, projectID, []ThreatHit{hit})
	if err != nil {
		t.Fatalf("reconcile hits: %v", err)
	}
	if len(fresh) != 1 {
		t.Fatalf("first reconcile newOrChanged = %d, want 1", len(fresh))
	}

	// Second identical sync must not duplicate the row nor re-notify.
	fresh, err = stores.Threats.ReconcileHits(ctx, projectID, []ThreatHit{hit})
	if err != nil {
		t.Fatalf("re-reconcile hits: %v", err)
	}
	if len(fresh) != 0 {
		t.Fatalf("second reconcile newOrChanged = %d, want 0 (no repeat notify)", len(fresh))
	}
	var count int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM project_inventory_hits WHERE project_id = $1`, projectID).Scan(&count); err != nil {
		t.Fatalf("count hits: %v", err)
	}
	if count != 1 {
		t.Fatalf("hit rows = %d, want 1 after double sync", count)
	}
}

func TestThreats_ReconcileHitsNotifySemantics(t *testing.T) {
	ctx := context.Background()
	pool := threatsTestPool(t)
	projectID := threatsTestProject(t, pool)
	stores := NewPostgresStores(pool, "")

	advs := []threats.Advisory{{
		AdvisoryID: "GHSA-TEST-RECON-2",
		Source:     "osv",
		CVEID:      "CVE-2024-0002",
		Severity:   "HIGH",
		AffectedPackages: []threats.AffectedPackage{
			{Ecosystem: "npm", Name: "lodash"},
		},
	}}
	if err := stores.Threats.UpsertAdvisories(ctx, advs, nil); err != nil {
		t.Fatalf("upsert advisories: %v", err)
	}

	hit := ThreatHit{
		AdvisoryID: "GHSA-TEST-RECON-2", PkgName: "lodash", PkgVersion: "4.17.20",
		InventoryStatus: "declared", MatchStatus: "unconfirmed",
	}
	if _, err := stores.Threats.ReconcileHits(ctx, projectID, []ThreatHit{hit}); err != nil {
		t.Fatalf("seed reconcile: %v", err)
	}

	// Promoted match_status must surface as a notify candidate.
	hit.MatchStatus = "active_threat"
	fresh, err := stores.Threats.ReconcileHits(ctx, projectID, []ThreatHit{hit})
	if err != nil {
		t.Fatalf("reconcile promoted match: %v", err)
	}
	if len(fresh) != 1 {
		t.Fatalf("promoted match newOrChanged = %d, want 1", len(fresh))
	}

	// Runtime-only promotion is persisted but must NOT notify.
	hit.RuntimeStatus = "L2"
	fresh, err = stores.Threats.ReconcileHits(ctx, projectID, []ThreatHit{hit})
	if err != nil {
		t.Fatalf("reconcile runtime promotion: %v", err)
	}
	if len(fresh) != 0 {
		t.Fatalf("runtime-only change newOrChanged = %d, want 0", len(fresh))
	}
	var runtime string
	if err := pool.QueryRow(ctx,
		`SELECT runtime_status FROM project_inventory_hits WHERE project_id = $1 AND advisory_id = $2`,
		projectID, "GHSA-TEST-RECON-2").Scan(&runtime); err != nil {
		t.Fatalf("read runtime: %v", err)
	}
	if runtime != "L2" {
		t.Fatalf("runtime_status = %q, want promoted L2", runtime)
	}

	// Runtime downgrade attempts keep the highest level.
	hit.RuntimeStatus = "L0"
	if _, err := stores.Threats.ReconcileHits(ctx, projectID, []ThreatHit{hit}); err != nil {
		t.Fatalf("reconcile runtime downgrade: %v", err)
	}
	if err := pool.QueryRow(ctx,
		`SELECT runtime_status FROM project_inventory_hits WHERE project_id = $1 AND advisory_id = $2`,
		projectID, "GHSA-TEST-RECON-2").Scan(&runtime); err != nil {
		t.Fatalf("read runtime after downgrade: %v", err)
	}
	if runtime != "L2" {
		t.Fatalf("runtime_status = %q after downgrade attempt, want kept L2", runtime)
	}
}

func TestThreats_NormalizeSeverity(t *testing.T) {
	cases := []struct {
		name string
		sev  string
		cvss float64
		want string
	}{
		{"cvss critical wins over type string", "CVSS_V3", 9.8, "critical"},
		{"cvss 9.0 boundary", "", 9.0, "critical"},
		{"cvss high", "CVSS_V3", 7.5, "high"},
		{"cvss 7.0 boundary", "", 7.0, "high"},
		{"cvss medium", "", 5.0, "medium"},
		{"cvss 4.0 boundary", "", 4.0, "medium"},
		{"cvss low", "", 2.0, "low"},
		{"uppercase enum accepted", "HIGH", 0, "high"},
		{"mixed case enum accepted", "Critical", 0, "critical"},
		{"osv type string falls back to info", "CVSS_V3", 0, "info"},
		{"empty falls back to info", "", 0, "info"},
		{"unknown string falls back to info", "MODERATE", 0, "info"},
	}
	for _, tc := range cases {
		if got := normalizeThreatSeverity(tc.sev, tc.cvss); got != tc.want {
			t.Errorf("%s: normalizeThreatSeverity(%q, %v) = %q, want %q",
				tc.name, tc.sev, tc.cvss, got, tc.want)
		}
	}
}

func TestThreats_KEVPersist(t *testing.T) {
	ctx := context.Background()
	pool := threatsTestPool(t)
	threatsTestProject(t, pool)
	stores := NewPostgresStores(pool, "")

	kevChecker := func(cveID string, aliases []string) bool {
		if cveID == "CVE-2021-44228" {
			return true
		}
		for _, a := range aliases {
			if a == "CVE-2021-44228" {
				return true
			}
		}
		return false
	}

	advs := []threats.Advisory{
		{
			AdvisoryID: "GHSA-TEST-KEV1",
			Source:     "osv",
			CVEID:      "CVE-2021-44228",
			Severity:   "CRITICAL",
			CVSS:       10.0,
		},
		{
			AdvisoryID: "GHSA-TEST-KEV2",
			Source:     "osv",
			CVEID:      "",
			Aliases:    []string{"CVE-2021-44228"},
			Severity:   "HIGH",
		},
		{
			AdvisoryID: "GHSA-TEST-NOKEV",
			Source:     "osv",
			CVEID:      "CVE-2024-99999",
			Severity:   "LOW",
		},
	}
	if err := stores.Threats.UpsertAdvisories(ctx, advs, kevChecker); err != nil {
		t.Fatalf("upsert advisories with kev: %v", err)
	}
	checkKEV := func(id string, want bool) {
		t.Helper()
		var kev bool
		if err := pool.QueryRow(ctx, `SELECT kev FROM threat_advisories WHERE advisory_id = $1`, id).Scan(&kev); err != nil {
			t.Fatalf("read kev flag %s: %v", id, err)
		}
		if kev != want {
			t.Fatalf("kev flag %s = %v, want %v", id, kev, want)
		}
	}
	checkKEV("GHSA-TEST-KEV1", true)
	checkKEV("GHSA-TEST-KEV2", true)
	checkKEV("GHSA-TEST-NOKEV", false)

	// KEV is ingest-owned: a later sync with an empty catalog must clear it.
	if err := stores.Threats.UpsertAdvisories(ctx, advs[:1], nil); err != nil {
		t.Fatalf("re-upsert without kev checker: %v", err)
	}
	checkKEV("GHSA-TEST-KEV1", false)
}

func TestThreats_SeverityPersist(t *testing.T) {
	ctx := context.Background()
	pool := threatsTestPool(t)
	threatsTestProject(t, pool)
	stores := NewPostgresStores(pool, "")

	advs := []threats.Advisory{
		{AdvisoryID: "GHSA-TEST-SEV1", Source: "osv", Severity: "CVSS_V3", CVSS: 9.8},
		{AdvisoryID: "GHSA-TEST-SEV2", Source: "osv", Severity: "CVSS_V3", CVSS: 0},
	}
	if err := stores.Threats.UpsertAdvisories(ctx, advs, nil); err != nil {
		t.Fatalf("upsert advisories: %v", err)
	}
	checkSev := func(id, want string) {
		t.Helper()
		var sev string
		if err := pool.QueryRow(ctx, `SELECT severity FROM threat_advisories WHERE advisory_id = $1`, id).Scan(&sev); err != nil {
			t.Fatalf("read severity %s: %v", id, err)
		}
		if sev != want {
			t.Fatalf("severity %s = %q, want %q", id, sev, want)
		}
	}
	checkSev("GHSA-TEST-SEV1", "critical")
	checkSev("GHSA-TEST-SEV2", "info")
}
