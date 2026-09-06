package threats

import (
	"testing"
)

// wantHit describes the expected shape of a single Hit.
type wantHit struct {
	AdvisoryID       string
	CVEID            string
	PkgName          string
	PkgVersion       string
	InventoryStatus  string
	KEV              bool
	MatchStatus      string
	EvidenceKeys     []string
	MissingEvidence  []string
}

func TestMatcher(t *testing.T) {
	kevEntry := func(cve string) KEVEntry {
		return KEVEntry{CVEID: cve, VendorProject: "vendor", Product: "product"}
	}

	tests := []struct {
		name       string
		inventory  []Dependency
		advisories []Advisory
		kev        map[string]KEVEntry
		findings   []FindingRef
		wantCount  int
		want       []wantHit
	}{
		{
			// S1: inventory row joins an advisory on normalized
			// ecosystem + lowercase name; evidence carries declared.
			name: "S1 inventory match carries declared evidence",
			inventory: []Dependency{
				{Ecosystem: "pip", Name: "Requests", Version: "2.28.0", SourceFile: "requirements.txt"},
			},
			advisories: []Advisory{
				{
					AdvisoryID: "GHSA-9hjg-9r4m-mvj7",
					CVEID:      "CVE-2023-32681",
					Severity:   "HIGH",
					AffectedPackages: []AffectedPackage{
						{Ecosystem: "PyPI", Name: "requests"},
					},
				},
			},
			kev:       nil,
			findings:  nil,
			wantCount: 1,
			want: []wantHit{
				{
					AdvisoryID:      "GHSA-9hjg-9r4m-mvj7",
					CVEID:           "CVE-2023-32681",
					PkgName:         "Requests",
					PkgVersion:      "2.28.0",
					InventoryStatus: "declared",
					KEV:             false,
					MatchStatus:     "unconfirmed",
					EvidenceKeys:    []string{"declared"},
					MissingEvidence: []string{"detected", "corroborated"},
				},
			},
		},
		{
			// S2: advisory with empty CVEID still flags KEV when an
			// alias is in the catalog.
			name: "S2 KEV match via alias",
			inventory: []Dependency{
				{Ecosystem: "npm", Name: "lodash", Version: "4.17.20", SourceFile: "package.json"},
			},
			advisories: []Advisory{
				{
					AdvisoryID: "GHSA-4xc9-xhrj-v574",
					CVEID:      "",
					Aliases:    []string{"CVE-2020-8203"},
					Severity:   "MODERATE",
					AffectedPackages: []AffectedPackage{
						{Ecosystem: "npm", Name: "lodash"},
					},
				},
			},
			kev: map[string]KEVEntry{
				"CVE-2020-8203": kevEntry("CVE-2020-8203"),
			},
			findings:  nil,
			wantCount: 1,
			want: []wantHit{
				{
					AdvisoryID:      "GHSA-4xc9-xhrj-v574",
					CVEID:           "",
					PkgName:         "lodash",
					PkgVersion:      "4.17.20",
					InventoryStatus: "declared",
					KEV:             true,
					MatchStatus:     "unconfirmed",
					EvidenceKeys:    []string{"declared"},
					MissingEvidence: []string{"detected", "corroborated"},
				},
			},
		},
		{
			// S4: declared-only hit (no finding corroboration) stays
			// unconfirmed even when the catalog is non-empty.
			name: "S4 declared-only stays unconfirmed",
			inventory: []Dependency{
				{Ecosystem: "go", Name: "github.com/gin-gonic/gin", Version: "v1.9.0", SourceFile: "go.mod"},
			},
			advisories: []Advisory{
				{
					AdvisoryID: "GO-2023-1234",
					CVEID:      "CVE-2023-99999",
					Severity:   "HIGH",
					AffectedPackages: []AffectedPackage{
						{Ecosystem: "Go", Name: "github.com/gin-gonic/gin"},
					},
				},
			},
			kev: map[string]KEVEntry{
				"CVE-2021-00001": kevEntry("CVE-2021-00001"),
			},
			findings:  nil,
			wantCount: 1,
			want: []wantHit{
				{
					AdvisoryID:      "GO-2023-1234",
					CVEID:           "CVE-2023-99999",
					PkgName:         "github.com/gin-gonic/gin",
					PkgVersion:      "v1.9.0",
					InventoryStatus: "declared",
					KEV:             false,
					MatchStatus:     "unconfirmed",
					EvidenceKeys:    []string{"declared"},
					MissingEvidence: []string{"detected", "corroborated"},
				},
			},
		},
		{
			name: "finding CVE match corroborates to active_threat",
			inventory: []Dependency{
				{Ecosystem: "pip", Name: "urllib3", Version: "1.26.5", SourceFile: "requirements.txt"},
			},
			advisories: []Advisory{
				{
					AdvisoryID: "GHSA-q2qg-gn5g-g2mf",
					CVEID:      "CVE-2021-33503",
					Aliases:    []string{"CVE-2021-33503"},
					Severity:   "CRITICAL",
					AffectedPackages: []AffectedPackage{
						{Ecosystem: "PyPI", Name: "urllib3"},
					},
				},
			},
			kev: map[string]KEVEntry{
				"CVE-2021-33503": kevEntry("CVE-2021-33503"),
			},
			findings: []FindingRef{
				{ID: "finding-1", PkgName: "urllib3", PkgVersion: "1.26.5", CVEID: "CVE-2021-33503"},
			},
			wantCount: 1,
			want: []wantHit{
				{
					AdvisoryID:      "GHSA-q2qg-gn5g-g2mf",
					CVEID:           "CVE-2021-33503",
					PkgName:         "urllib3",
					PkgVersion:      "1.26.5",
					InventoryStatus: "corroborated",
					KEV:             true,
					MatchStatus:     "active_threat",
					EvidenceKeys:    []string{"declared", "detected", "corroborated"},
				},
			},
		},
		{
			name: "finding pkg name+version match corroborates without CVE",
			inventory: []Dependency{
				{Ecosystem: "cargo", Name: "serde", Version: "1.0.150", SourceFile: "Cargo.lock"},
			},
			advisories: []Advisory{
				{
					AdvisoryID: "GHSA-xxxx-yyyy-zzzz",
					CVEID:      "CVE-2022-11111",
					AffectedPackages: []AffectedPackage{
						{Ecosystem: "crates.io", Name: "Serde"},
					},
				},
			},
			kev: nil,
			findings: []FindingRef{
				{ID: "finding-2", PkgName: "SERDE", PkgVersion: "1.0.150", CVEID: ""},
			},
			wantCount: 1,
			want: []wantHit{
				{
					AdvisoryID:      "GHSA-xxxx-yyyy-zzzz",
					CVEID:           "CVE-2022-11111",
					PkgName:         "serde",
					PkgVersion:      "1.0.150",
					InventoryStatus: "corroborated",
					KEV:             false,
					MatchStatus:     "active_threat",
					EvidenceKeys:    []string{"declared", "detected", "corroborated"},
				},
			},
		},
		{
			name:      "finding-only match yields detected hit",
			inventory: nil,
			advisories: []Advisory{
				{
					AdvisoryID: "GHSA-det-only-1",
					CVEID:      "CVE-2024-22222",
					AffectedPackages: []AffectedPackage{
						{Ecosystem: "npm", Name: "minimist"},
					},
				},
			},
			kev: nil,
			findings: []FindingRef{
				{ID: "finding-3", PkgName: "minimist", PkgVersion: "1.2.5", CVEID: "CVE-2024-22222"},
			},
			wantCount: 1,
			want: []wantHit{
				{
					AdvisoryID:      "GHSA-det-only-1",
					CVEID:           "CVE-2024-22222",
					PkgName:         "minimist",
					PkgVersion:      "1.2.5",
					InventoryStatus: "detected",
					KEV:             false,
					MatchStatus:     "unconfirmed",
					EvidenceKeys:    []string{"detected"},
					MissingEvidence: []string{"declared", "corroborated"},
				},
			},
		},
		{
			name:      "kev plus detected-only yields active_threat",
			inventory: nil,
			advisories: []Advisory{
				{
					AdvisoryID: "GHSA-det-kev-1",
					CVEID:      "CVE-2024-33333",
					AffectedPackages: []AffectedPackage{
						{Ecosystem: "npm", Name: "minimist"},
					},
				},
			},
			kev: map[string]KEVEntry{
				"CVE-2024-33333": kevEntry("CVE-2024-33333"),
			},
			findings: []FindingRef{
				{ID: "finding-4", PkgName: "minimist", PkgVersion: "1.2.5", CVEID: "CVE-2024-33333"},
			},
			wantCount: 1,
			want: []wantHit{
				{
					AdvisoryID:      "GHSA-det-kev-1",
					CVEID:           "CVE-2024-33333",
					PkgName:         "minimist",
					PkgVersion:      "1.2.5",
					InventoryStatus: "detected",
					KEV:             true,
					MatchStatus:     "active_threat",
					EvidenceKeys:    []string{"detected"},
					MissingEvidence: []string{"declared", "corroborated"},
				},
			},
		},
		{
			name: "unrelated advisory produces no hits",
			inventory: []Dependency{
				{Ecosystem: "npm", Name: "react", Version: "18.2.0", SourceFile: "package.json"},
			},
			advisories: []Advisory{
				{
					AdvisoryID: "GHSA-nope-1",
					CVEID:      "CVE-2024-44444",
					AffectedPackages: []AffectedPackage{
						{Ecosystem: "npm", Name: "minimist"},
					},
				},
			},
			kev:       nil,
			findings:  nil,
			wantCount: 0,
			want:      nil,
		},
		{
			name: "unknown ecosystem never matches",
			inventory: []Dependency{
				{Ecosystem: "maven", Name: "log4j", Version: "2.14.0", SourceFile: "pom.xml"},
			},
			advisories: []Advisory{
				{
					AdvisoryID: "GHSA-nope-2",
					CVEID:      "CVE-2021-44228",
					AffectedPackages: []AffectedPackage{
						{Ecosystem: "Maven", Name: "log4j"},
					},
				},
			},
			kev:       nil,
			findings:  nil,
			wantCount: 0,
			want:      nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Match(tc.inventory, tc.advisories, tc.kev, tc.findings)
			if len(got) != tc.wantCount {
				t.Fatalf("Match() returned %d hits, want %d (%v)", len(got), tc.wantCount, got)
			}
			for i, w := range tc.want {
				h := got[i]
				if h.AdvisoryID != w.AdvisoryID {
					t.Errorf("hit %d AdvisoryID = %q, want %q", i, h.AdvisoryID, w.AdvisoryID)
				}
				if h.CVEID != w.CVEID {
					t.Errorf("hit %d CVEID = %q, want %q", i, h.CVEID, w.CVEID)
				}
				if h.PkgName != w.PkgName {
					t.Errorf("hit %d PkgName = %q, want %q", i, h.PkgName, w.PkgName)
				}
				if h.PkgVersion != w.PkgVersion {
					t.Errorf("hit %d PkgVersion = %q, want %q", i, h.PkgVersion, w.PkgVersion)
				}
				if h.InventoryStatus != w.InventoryStatus {
					t.Errorf("hit %d InventoryStatus = %q, want %q", i, h.InventoryStatus, w.InventoryStatus)
				}
				if h.KEV != w.KEV {
					t.Errorf("hit %d KEV = %v, want %v", i, h.KEV, w.KEV)
				}
				if h.MatchStatus != w.MatchStatus {
					t.Errorf("hit %d MatchStatus = %q, want %q", i, h.MatchStatus, w.MatchStatus)
				}
				for _, key := range w.EvidenceKeys {
					if _, ok := h.Evidence[key]; !ok {
						t.Errorf("hit %d Evidence missing key %q (have %v)", i, key, h.Evidence)
					}
				}
				for _, key := range w.MissingEvidence {
					if _, ok := h.Evidence[key]; ok {
						t.Errorf("hit %d Evidence must not contain key %q", i, key)
					}
				}
			}
		})
	}
}
