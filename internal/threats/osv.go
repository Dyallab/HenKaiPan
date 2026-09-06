// Package threats provides threat-intelligence clients (OSV, CISA KEV)
// for the HenKaiPan threat-intel MVP (issue #64).
//
// MERGE POINT (Dependency): the canonical Dependency type lives in
// manifest.go (owned by the manifest-parsing task). It is NOT defined here
// on purpose — this file only consumes it. If the package fails to compile
// with "undefined: Dependency", manifest.go has not landed yet.
package threats

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	// osvMaxBatchSize is the OSV API limit per querybatch call.
	osvMaxBatchSize = 1000
	// osvMaxBodyBytes caps response bodies (32MB).
	osvMaxBodyBytes = 32 << 20
	// osvHydrationWorkers bounds GET /v1/vulns/{id} fan-out.
	osvHydrationWorkers = 8
	// defaultOSVBaseURL is the production OSV endpoint.
	defaultOSVBaseURL = "https://api.osv.dev"
)

// Advisory is the normalized output of the OSV client.
type Advisory struct {
	AdvisoryID       string
	Source           string
	CVEID            string
	Aliases          []string
	Severity         string
	CVSS             float64
	AffectedPackages []AffectedPackage
	Published        time.Time
	Raw              json.RawMessage
}

// AffectedPackage is one affected entry with its version ranges.
type AffectedPackage struct {
	Ecosystem string
	Name      string
	Ranges    []AffectedRange
}

// AffectedRange is a single version range (e.g. SEMVER events).
type AffectedRange struct {
	Type   string
	Events []RangeEvent
}

// RangeEvent holds introduced/fixed version bounds.
type RangeEvent struct {
	Introduced string
	Fixed      string
}

// Client queries OSV. BaseURL is configurable so tests can point at httptest.
type Client struct {
	BaseURL    string
	Version    string
	httpClient *http.Client
}

// NewClient builds an OSV client with a 30s HTTP timeout.
func NewClient(baseURL, version string) *Client {
	if strings.TrimSpace(baseURL) == "" {
		baseURL = defaultOSVBaseURL
	}
	return &Client{
		BaseURL:    strings.TrimSuffix(baseURL, "/"),
		Version:    version,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

// QueryHit pairs one queried Dependency with one Advisory the OSV server
// returned for that exact query, preserving the query→dependency
// association that a globally deduped []Advisory cannot carry.
type QueryHit struct {
	Dependency Dependency
	Advisory   Advisory
}

// Query resolves deps to advisories: chunked POST /v1/querybatch for IDs,
// then bounded hydration of each ID via GET /v1/vulns/{id}.
// Server-side version matching is trusted — no range comparison here.
// Hydration failures are tolerated (skipped), never fatal.
func (c *Client) Query(ctx context.Context, deps []Dependency) ([]Advisory, error) {
	hits, err := c.QueryBatchWithDeps(ctx, deps)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]struct{}, len(hits))
	out := make([]Advisory, 0, len(hits))
	for _, h := range hits {
		if h.Advisory.AdvisoryID == "" {
			continue
		}
		if _, ok := seen[h.Advisory.AdvisoryID]; ok {
			continue
		}
		seen[h.Advisory.AdvisoryID] = struct{}{}
		out = append(out, h.Advisory)
	}
	return out, nil
}

// QueryBatchWithDeps resolves deps to per-dependency query hits, retaining
// which advisory was returned for which dependency version. Two versions of
// the same package that match the same advisory yield two hits sharing that
// advisory; callers (e.g. MatchQueryHits) decide per-dep applicability from
// the advisory's affected ranges. Query is implemented in terms of this
// method and keeps its global-dedup contract.
func (c *Client) QueryBatchWithDeps(ctx context.Context, deps []Dependency) ([]QueryHit, error) {
	queryable := make([]Dependency, 0, len(deps))
	for _, d := range deps {
		if strings.TrimSpace(d.Name) == "" || strings.TrimSpace(d.Version) == "" {
			continue
		}
		if OSVEcosystem(d.Ecosystem) == "" {
			continue
		}
		queryable = append(queryable, d)
	}

	perQuery := make([][]string, 0, len(queryable))
	for _, chunk := range chunkDeps(queryable, osvMaxBatchSize) {
		chunkIDs, err := c.queryBatchIndexed(ctx, chunk)
		if err != nil {
			return nil, err
		}
		perQuery = append(perQuery, chunkIDs...)
	}

	unique := dedupe(flattenIDs(perQuery))
	hydrated := c.hydrate(ctx, unique)
	byID := make(map[string]Advisory, len(hydrated))
	for _, a := range hydrated {
		byID[a.AdvisoryID] = a
	}

	var out []QueryHit
	for i, dep := range queryable {
		for _, id := range perQuery[i] {
			a, ok := byID[id]
			if !ok {
				continue
			}
			out = append(out, QueryHit{Dependency: dep, Advisory: a})
		}
	}
	return out, nil
}

func flattenIDs(perQuery [][]string) []string {
	var out []string
	for _, ids := range perQuery {
		out = append(out, ids...)
	}
	return out
}

func chunkDeps(deps []Dependency, size int) [][]Dependency {
	var chunks [][]Dependency
	for i := 0; i < len(deps); i += size {
		end := i + size
		if end > len(deps) {
			end = len(deps)
		}
		chunks = append(chunks, deps[i:end])
	}
	return chunks
}

func dedupe(ids []string) []string {
	seen := make(map[string]struct{}, len(ids))
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out
}

type osvPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type osvQuery struct {
	Package osvPackage `json:"package"`
	Version string     `json:"version"`
}

type osvBatchResponse struct {
	Results []struct {
		Vulns []struct {
			ID       string `json:"id"`
			Modified string `json:"modified"`
		} `json:"vulns"`
	} `json:"results"`
}

// queryBatch POSTs one chunk (≤1000 queries) and returns the matched vuln IDs.
func (c *Client) queryBatch(ctx context.Context, chunk []Dependency) ([]string, error) {
	perQuery, err := c.queryBatchIndexed(ctx, chunk)
	if err != nil {
		return nil, err
	}
	return flattenIDs(perQuery), nil
}

// queryBatchIndexed POSTs one chunk and returns matched vuln IDs aligned
// 1:1 with the chunk order, so callers can tell which IDs belong to which
// queried dependency. Short server results are padded with empty sets.
func (c *Client) queryBatchIndexed(ctx context.Context, chunk []Dependency) ([][]string, error) {
	queries := make([]osvQuery, 0, len(chunk))
	for _, d := range chunk {
		queries = append(queries, osvQuery{
			Package: osvPackage{Name: d.Name, Ecosystem: OSVEcosystem(d.Ecosystem)},
			Version: d.Version,
		})
	}
	body, err := c.doJSON(ctx, http.MethodPost, c.BaseURL+"/v1/querybatch",
		map[string]any{"queries": queries})
	if err != nil {
		return nil, err
	}
	var resp osvBatchResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("osv: decode querybatch: %w", err)
	}
	perQuery := make([][]string, len(chunk))
	for i := range resp.Results {
		if i >= len(chunk) {
			break
		}
		for _, v := range resp.Results[i].Vulns {
			perQuery[i] = append(perQuery[i], v.ID)
		}
	}
	return perQuery, nil
}

type osvVuln struct {
	ID       string   `json:"id"`
	Aliases  []string `json:"aliases"`
	Severity []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	Affected []struct {
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
		Ranges []struct {
			Type   string              `json:"type"`
			Events []map[string]string `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
	Published string `json:"published"`
}

// hydrate fans out GET /v1/vulns/{id} over a bounded worker pool.
// Individual failures are skipped so one bad record never fails the batch.
func (c *Client) hydrate(ctx context.Context, ids []string) []Advisory {
	sem := make(chan struct{}, osvHydrationWorkers)
	var wg sync.WaitGroup
	var mu sync.Mutex
	out := make([]Advisory, 0, len(ids))

	for _, id := range ids {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}
			a, err := c.hydrateOne(ctx, id)
			if err != nil {
				return
			}
			mu.Lock()
			out = append(out, a)
			mu.Unlock()
		}(id)
	}
	wg.Wait()
	return out
}

func (c *Client) hydrateOne(ctx context.Context, id string) (Advisory, error) {
	body, err := c.doJSON(ctx, http.MethodGet, c.BaseURL+"/v1/vulns/"+id, nil)
	if err != nil {
		return Advisory{}, err
	}
	var v osvVuln
	if err := json.Unmarshal(body, &v); err != nil {
		return Advisory{}, fmt.Errorf("osv: decode vuln %s: %w", id, err)
	}

	a := Advisory{
		AdvisoryID: v.ID,
		Source:     "osv",
		Aliases:    v.Aliases,
		Raw:        append(json.RawMessage(nil), body...),
	}
	for _, alias := range v.Aliases {
		if strings.HasPrefix(alias, "CVE-") {
			a.CVEID = alias
			break
		}
	}
	if len(v.Severity) > 0 {
		a.Severity = v.Severity[0].Type
		a.CVSS = cvssScore(v.Severity[0].Score)
	}
	for _, aff := range v.Affected {
		ap := AffectedPackage{Ecosystem: aff.Package.Ecosystem, Name: aff.Package.Name}
		for _, r := range aff.Ranges {
			ar := AffectedRange{Type: r.Type}
			for _, e := range r.Events {
				ar.Events = append(ar.Events, RangeEvent{
					Introduced: e["introduced"],
					Fixed:      e["fixed"],
				})
			}
			ap.Ranges = append(ap.Ranges, ar)
		}
		a.AffectedPackages = append(a.AffectedPackages, ap)
	}
	if v.Published != "" {
		if ts, err := time.Parse(time.RFC3339, v.Published); err == nil {
			a.Published = ts
		}
	}
	return a, nil
}

// doJSON performs an HTTP request with context, JSON content type and a
// custom User-Agent, capping the response body at 32MB.
func (c *Client) doJSON(ctx context.Context, method, url string, payload any) ([]byte, error) {
	var r io.Reader
	if payload != nil {
		buf, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("osv: marshal request: %w", err)
		}
		r = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, r)
	if err != nil {
		return nil, fmt.Errorf("osv: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "henkaipan/"+c.Version)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("osv: request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("osv: server returned %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, osvMaxBodyBytes))
}

// cvssScore parses an OSV severity score: either a plain number ("7.5") or
// a CVSS v3.x vector ("CVSS:3.1/AV:N/..."). Unknown formats yield 0.
func cvssScore(score string) float64 {
	if f, err := parseFloat(score); err == nil {
		return f
	}
	if strings.HasPrefix(score, "CVSS:3.") {
		if f, ok := cvssV3Base(score); ok {
			return f
		}
	}
	return 0
}

func cvssV3Base(vector string) (float64, bool) {
	m := map[string]string{}
	for _, part := range strings.Split(vector, "/") {
		kv := strings.SplitN(part, ":", 2)
		if len(kv) == 2 {
			m[kv[0]] = kv[1]
		}
	}
	av := map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[m["AV"]]
	ac := map[string]float64{"L": 0.77, "H": 0.44}[m["AC"]]
	ui := map[string]float64{"N": 0.85, "R": 0.62}[m["UI"]]
	c := map[string]float64{"N": 0, "L": 0.22, "H": 0.56}[m["C"]]
	i := map[string]float64{"N": 0, "L": 0.22, "H": 0.56}[m["I"]]
	a := map[string]float64{"N": 0, "L": 0.22, "H": 0.56}[m["A"]]
	if m["AV"] == "" || m["AC"] == "" || m["UI"] == "" || m["C"] == "" || m["I"] == "" || m["A"] == "" {
		return 0, false
	}
	changed := m["S"] == "C"
	var pr float64
	switch m["PR"] {
	case "N":
		pr = 0.85
	case "L":
		if changed {
			pr = 0.68
		} else {
			pr = 0.62
		}
	case "H":
		if changed {
			pr = 0.5
		} else {
			pr = 0.27
		}
	default:
		return 0, false
	}
	isc := 1 - (1-c)*(1-i)*(1-a)
	if isc <= 0 {
		return 0, true
	}
	exploit := 8.22 * av * ac * pr * ui
	var impact float64
	if changed {
		impact = 7.52*(isc-0.029) - 3.25*pow15(isc-0.02)
	} else {
		impact = 6.42 * isc
	}
	var base float64
	if changed {
		base = minFloat(1.08*(impact+exploit), 10)
	} else {
		base = minFloat(impact+exploit, 10)
	}
	return roundUp1(base), true
}

func pow15(x float64) float64 {
	if x <= 0 {
		return 0
	}
	p := 1.0
	for range 15 {
		p *= x
	}
	return p
}

func roundUp1(x float64) float64 {
	n := int(x * 10)
	if float64(n)/10 < x {
		n++
	}
	return float64(n) / 10
}

func minFloat(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

func parseFloat(s string) (float64, error) {
	var f float64
	_, err := fmt.Sscanf(strings.TrimSpace(s), "%g", &f)
	if err != nil {
		return 0, err
	}
	return f, nil
}
