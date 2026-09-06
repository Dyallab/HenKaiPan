package threats

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

const kevFixture = `{
	"catalogVersion": "2024.01.01",
	"dateReleased": "2024-01-01T00:00:00.000Z",
	"count": 3,
	"vulnerabilities": [
		{
			"cveID": "CVE-2021-44228",
			"vendorProject": "Apache",
			"product": "Log4j2",
			"vulnerabilityName": "Apache Log4j2 Remote Code Execution Vulnerability",
			"dateAdded": "2021-12-10",
			"shortDescription": "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP.",
			"requiredAction": "Apply updates per vendor instructions.",
			"dueDate": "2021-12-24",
			"knownRansomwareCampaignUse": "Known"
		},
		{
			"cveID": "CVE-2023-34362",
			"vendorProject": "Progress",
			"product": "MOVEit Transfer",
			"vulnerabilityName": "Progress MOVEit Transfer SQL Injection Vulnerability",
			"dateAdded": "2023-06-02",
			"shortDescription": "Progress MOVEit Transfer contains an SQL injection vulnerability.",
			"requiredAction": "Apply updates per vendor instructions.",
			"dueDate": "2023-06-23",
			"knownRansomwareCampaignUse": "Known"
		},
		{
			"cveID": "CVE-2024-21887",
			"vendorProject": "Ivanti",
			"product": "Connect Secure",
			"vulnerabilityName": "Ivanti Connect Secure Command Injection Vulnerability",
			"dateAdded": "2024-01-12",
			"shortDescription": "Ivanti Connect Secure contains a command injection vulnerability.",
			"requiredAction": "Apply mitigations per vendor instructions.",
			"dueDate": "2024-02-02",
			"knownRansomwareCampaignUse": "Unknown"
		}
	]
}`

func fixtureServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(kevFixture))
	}))
}

func TestKEVFetch(t *testing.T) {
	srv := fixtureServer(t)
	defer srv.Close()

	client := &http.Client{Timeout: 30 * time.Second}
	got, err := FetchKEV(context.Background(), client, srv.URL)
	if err != nil {
		t.Fatalf("FetchKEV returned error: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("FetchKEV returned %d entries, want 3", len(got))
	}
	for _, cve := range []string{"CVE-2021-44228", "CVE-2023-34362", "CVE-2024-21887"} {
		if _, ok := got[cve]; !ok {
			t.Errorf("FetchKEV missing key %s", cve)
		}
	}

	entry := got["CVE-2021-44228"]
	if entry.VendorProject != "Apache" {
		t.Errorf("VendorProject = %q, want %q", entry.VendorProject, "Apache")
	}
	if entry.Product != "Log4j2" {
		t.Errorf("Product = %q, want %q", entry.Product, "Log4j2")
	}
	if entry.KnownRansomwareCampaignUse != "Known" {
		t.Errorf("KnownRansomwareCampaignUse = %q, want %q", entry.KnownRansomwareCampaignUse, "Known")
	}
	if entry.DueDate != "2024-02-02" && entry.CVEID == "CVE-2024-21887" {
		t.Errorf("unexpected due date")
	}
	ivanti := got["CVE-2024-21887"]
	if ivanti.DueDate != "2024-02-02" {
		t.Errorf("DueDate = %q, want %q", ivanti.DueDate, "2024-02-02")
	}
	if ivanti.RequiredAction == "" || ivanti.ShortDescription == "" || ivanti.VulnerabilityName == "" {
		t.Errorf("expected description/action/name to be populated: %+v", ivanti)
	}
}

func TestKEVDiff(t *testing.T) {
	srv := fixtureServer(t)
	defer srv.Close()

	client := &http.Client{Timeout: 30 * time.Second}
	fresh, err := FetchKEV(context.Background(), client, srv.URL)
	if err != nil {
		t.Fatalf("FetchKEV returned error: %v", err)
	}

	old := map[string]KEVEntry{
		"CVE-2021-44228": fresh["CVE-2021-44228"],
		"CVE-2020-0001":  {CVEID: "CVE-2020-0001", VendorProject: "Example", Product: "Old"},
	}

	added, removed := DiffKEV(old, fresh)

	addedSet := map[string]bool{}
	for _, cve := range added {
		addedSet[cve] = true
	}
	removedSet := map[string]bool{}
	for _, cve := range removed {
		removedSet[cve] = true
	}

	for _, want := range []string{"CVE-2023-34362", "CVE-2024-21887"} {
		if !addedSet[want] {
			t.Errorf("DiffKEV added missing %s (got %v)", want, added)
		}
	}
	if addedSet["CVE-2021-44228"] {
		t.Errorf("DiffKEV added should not contain unchanged CVE-2021-44228 (got %v)", added)
	}
	if !removedSet["CVE-2020-0001"] {
		t.Errorf("DiffKEV removed missing CVE-2020-0001 (got %v)", removed)
	}
	if len(removed) != 1 {
		t.Errorf("DiffKEV removed = %v, want exactly [CVE-2020-0001]", removed)
	}
}

func TestKEVIsKEV(t *testing.T) {
	srv := fixtureServer(t)
	defer srv.Close()

	client := &http.Client{Timeout: 30 * time.Second}
	kev, err := FetchKEV(context.Background(), client, srv.URL)
	if err != nil {
		t.Fatalf("FetchKEV returned error: %v", err)
	}

	// Direct hit on primary cveID.
	if !IsKEV("CVE-2021-44228", nil, kev) {
		t.Errorf("IsKEV(CVE-2021-44228) = false, want true")
	}
	// Alias join: primary unknown but one alias is in the catalog.
	if !IsKEV("CVE-9999-0000", []string{"GHSA-xxxx-yyyy", "CVE-2023-34362"}, kev) {
		t.Errorf("IsKEV with KEV alias = false, want true")
	}
	// No match anywhere.
	if IsKEV("CVE-9999-0000", []string{"GHSA-xxxx-yyyy", "CVE-2020-0001"}, kev) {
		t.Errorf("IsKEV unknown = true, want false")
	}
	// Nil map is not KEV.
	if IsKEV("CVE-2021-44228", nil, nil) {
		t.Errorf("IsKEV with nil map = true, want false")
	}
}
