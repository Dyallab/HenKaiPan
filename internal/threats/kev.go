// Package threats — CISA KEV catalog client (issue #64).
package threats

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// KEVCatalogURL is the default CISA Known Exploited Vulnerabilities feed.
const KEVCatalogURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

// kevHTTPTimeout mirrors the telemetry client idiom (NewRequestWithContext +
// explicit client timeout) for outbound feed fetches.
const kevHTTPTimeout = 30 * time.Second

// KEVEntry is one CISA Known Exploited Vulnerability record.
type KEVEntry struct {
	CVEID                      string
	VendorProject              string
	Product                    string
	VulnerabilityName          string
	DateAdded                  string
	ShortDescription           string
	RequiredAction             string
	DueDate                    string
	KnownRansomwareCampaignUse string
}

// kevCatalog mirrors the CISA feed envelope.
type kevCatalog struct {
	CatalogVersion  string `json:"catalogVersion"`
	DateReleased    string `json:"dateReleased"`
	Count           int    `json:"count"`
	Vulnerabilities []struct {
		CveID                      string `json:"cveID"`
		VendorProject              string `json:"vendorProject"`
		Product                    string `json:"product"`
		VulnerabilityName          string `json:"vulnerabilityName"`
		DateAdded                  string `json:"dateAdded"`
		ShortDescription           string `json:"shortDescription"`
		RequiredAction             string `json:"requiredAction"`
		DueDate                    string `json:"dueDate"`
		KnownRansomwareCampaignUse string `json:"knownRansomwareCampaignUse"`
	} `json:"vulnerabilities"`
}

// FetchKEV downloads the CISA KEV catalog and indexes it by CVE ID.
// A nil client gets a 30s-timeout default; an empty url selects KEVCatalogURL.
func FetchKEV(ctx context.Context, client *http.Client, url string) (map[string]KEVEntry, error) {
	if client == nil {
		client = &http.Client{Timeout: kevHTTPTimeout}
	}
	if url == "" {
		url = KEVCatalogURL
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("kev: build request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("kev: request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("kev: server returned %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, fmt.Errorf("kev: read body: %w", err)
	}
	var catalog kevCatalog
	if err := json.Unmarshal(body, &catalog); err != nil {
		return nil, fmt.Errorf("kev: decode catalog: %w", err)
	}
	out := make(map[string]KEVEntry, len(catalog.Vulnerabilities))
	for _, v := range catalog.Vulnerabilities {
		if v.CveID == "" {
			continue
		}
		out[v.CveID] = KEVEntry{
			CVEID:                      v.CveID,
			VendorProject:              v.VendorProject,
			Product:                    v.Product,
			VulnerabilityName:          v.VulnerabilityName,
			DateAdded:                  v.DateAdded,
			ShortDescription:           v.ShortDescription,
			RequiredAction:             v.RequiredAction,
			DueDate:                    v.DueDate,
			KnownRansomwareCampaignUse: v.KnownRansomwareCampaignUse,
		}
	}
	return out, nil
}

// DiffKEV returns (added, removed) CVE IDs comparing old vs fresh catalogs.
func DiffKEV(old, fresh map[string]KEVEntry) (added, removed []string) {
	for cve := range fresh {
		if _, ok := old[cve]; !ok {
			added = append(added, cve)
		}
	}
	for cve := range old {
		if _, ok := fresh[cve]; !ok {
			removed = append(removed, cve)
		}
	}
	return added, removed
}

// IsKEV reports whether cveID or any alias is in the KEV catalog.
func IsKEV(cveID string, aliases []string, kev map[string]KEVEntry) bool {
	if len(kev) == 0 {
		return false
	}
	if _, ok := kev[cveID]; ok {
		return true
	}
	for _, a := range aliases {
		if _, ok := kev[a]; ok {
			return true
		}
	}
	return false
}
