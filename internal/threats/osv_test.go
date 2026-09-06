package threats

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// mockOSV builds an httptest server emulating:
//
//	POST /v1/querybatch -> {results:[{vulns:[{id,modified}]}]}, one vuln per query
//	GET  /v1/vulns/{id}  -> full record; id "FAIL-1" returns 500 to prove tolerance.
func mockOSV(t *testing.T, batchCalls *atomic.Int64, batchSizes *[]int, failID string) *httptest.Server {
	t.Helper()
	var sizes []int
	mux := http.NewServeMux()

	mux.HandleFunc("/v1/querybatch", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			http.Error(w, "bad content-type", http.StatusBadRequest)
			return
		}
		batchCalls.Add(1)
		var req struct {
			Queries []struct {
				Package struct {
					Name      string `json:"name"`
					Ecosystem string `json:"ecosystem"`
				} `json:"package"`
				Version string `json:"version"`
			} `json:"queries"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		sizes = append(sizes, len(req.Queries))
		*batchSizes = sizes

		type idOnly struct {
			ID       string `json:"id"`
			Modified string `json:"modified"`
		}
		results := make([]map[string]any, 0, len(req.Queries))
		for i, q := range req.Queries {
			// Version must be top-level, never inside purl — reject purl-shaped bodies.
			raw, _ := json.Marshal(q)
			if strings.Contains(string(raw), "purl") {
				http.Error(w, "version must not be sent inside purl", http.StatusBadRequest)
				return
			}
			if q.Version == "" {
				results = append(results, map[string]any{})
				continue
			}
			id := fmt.Sprintf("GHSA-test-%d", batchCalls.Load()*10000+int64(i))
			if failID != "" && i == 0 {
				id = failID
			}
			results = append(results, map[string]any{
				"vulns": []idOnly{{ID: id, Modified: "2024-01-01T00:00:00Z"}},
			})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"results": results})
	})

	mux.HandleFunc("/v1/vulns/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/v1/vulns/")
		if id == failID {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":       id,
			"aliases":  []string{"CVE-2024-1234"},
			"severity": []map[string]string{{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}},
			"affected": []map[string]any{
				{
					"package": map[string]string{"name": "left-pad", "ecosystem": "npm"},
					"ranges": []map[string]any{
						{"type": "SEMVER", "events": []map[string]string{{"introduced": "0"}, {"fixed": "1.3.1"}}},
					},
				},
			},
			"published": "2024-01-02T00:00:00Z",
			"modified":  "2024-01-03T00:00:00Z",
			"summary":   "test vuln",
		})
	})

	return httptest.NewServer(mux)
}

func testDeps(n int) []Dependency {
	deps := make([]Dependency, 0, n)
	for i := 0; i < n; i++ {
		deps = append(deps, Dependency{
			Ecosystem: "npm",
			Name:      fmt.Sprintf("pkg-%d", i),
			Version:   "1.0.0",
		})
	}
	return deps
}

func TestOSVChunking(t *testing.T) {
	var batchCalls atomic.Int64
	var batchSizes []int
	srv := mockOSV(t, &batchCalls, &batchSizes, "")
	defer srv.Close()

	c := NewClient(srv.URL, "test")
	advisories, err := c.Query(t.Context(), testDeps(1001))
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if got := batchCalls.Load(); got != 2 {
		t.Fatalf("expected 2 batch calls for 1001 inputs, got %d", got)
	}
	if len(batchSizes) != 2 || batchSizes[0] != 1000 || batchSizes[1] != 1 {
		t.Fatalf("expected chunk sizes [1000 1], got %v", batchSizes)
	}
	if len(advisories) != 1001 {
		t.Fatalf("expected 1001 advisories, got %d", len(advisories))
	}
}

func TestOSVHydration(t *testing.T) {
	var batchCalls atomic.Int64
	var batchSizes []int
	srv := mockOSV(t, &batchCalls, &batchSizes, "")
	defer srv.Close()

	c := NewClient(srv.URL, "test")
	advisories, err := c.Query(t.Context(), []Dependency{
		{Ecosystem: "npm", Name: "left-pad", Version: "1.0.0"},
	})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(advisories) != 1 {
		t.Fatalf("expected 1 advisory, got %d", len(advisories))
	}
	a := advisories[0]
	if a.Source != "osv" {
		t.Errorf("Source = %q, want osv", a.Source)
	}
	if len(a.Aliases) == 0 || a.Aliases[0] != "CVE-2024-1234" {
		t.Errorf("Aliases = %v, want [CVE-2024-1234]", a.Aliases)
	}
	if a.CVEID != "CVE-2024-1234" {
		t.Errorf("CVEID = %q, want CVE-2024-1234", a.CVEID)
	}
	if a.Severity == "" {
		t.Error("Severity empty, want CVSS severity")
	}
	if a.CVSS <= 0 {
		t.Errorf("CVSS = %v, want > 0", a.CVSS)
	}
	if len(a.AffectedPackages) == 0 {
		t.Fatal("AffectedPackages empty")
	}
	if a.Published.IsZero() {
		t.Error("Published zero time")
	}
	if len(a.Raw) == 0 {
		t.Error("Raw empty")
	}
}

func TestOSVPartialFailure(t *testing.T) {
	var batchCalls atomic.Int64
	var batchSizes []int
	srv := mockOSV(t, &batchCalls, &batchSizes, "FAIL-1")
	defer srv.Close()

	c := NewClient(srv.URL, "test")
	advisories, err := c.Query(t.Context(), []Dependency{
		{Ecosystem: "npm", Name: "bad", Version: "1.0.0"},
		{Ecosystem: "npm", Name: "good", Version: "2.0.0"},
	})
	if err != nil {
		t.Fatalf("Query must tolerate hydration failures, got err: %v", err)
	}
	if len(advisories) != 1 {
		t.Fatalf("expected 1 advisory (failed hydration skipped), got %d", len(advisories))
	}
}
