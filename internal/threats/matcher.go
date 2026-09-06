// Package threats — inventory × advisory × KEV × findings matcher (issue #64).
//
// Match is a pure function: it joins manifest inventory rows against OSV
// advisories, flags KEV-listed CVEs, and corroborates hits with pre-existing
// scanner findings. It performs no DB or HTTP I/O.
package threats

import (
	"strings"
)

// FindingRef is a pre-existing scanner finding that may corroborate a
// threat-intel hit.
type FindingRef struct {
	ID         string
	PkgName    string
	PkgVersion string
	CVEID      string
}

// Hit is one inventory/advisory join row with its evidence and verdict.
type Hit struct {
	AdvisoryID      string
	CVEID           string
	PkgName         string
	PkgVersion      string
	InventoryStatus string // declared | detected | corroborated
	KEV             bool
	MatchStatus     string // unconfirmed | active_threat
	Evidence        map[string]any
}

// Inventory / match status values emitted by Match.
const (
	StatusDeclared     = "declared"
	StatusDetected     = "detected"
	StatusCorroborated = "corroborated"

	MatchUnconfirmed  = "unconfirmed"
	MatchActiveThreat = "active_threat"
)

// Match joins inventory rows with advisories on OSVEcosystem-normalized
// ecosystem plus lowercase package name, flags KEV membership via IsKEV, and
// folds in findings as detection evidence.
//
// Evidence keys: "declared" is set when the manifest inventory matched,
// "detected" when a finding matches the same advisory (by CVEID/alias or by
// package name+version), "corroborated" when both hold. A finding that
// matches an advisory with no inventory row yields a detected-only hit.
// MatchStatus is active_threat when corroborated or when (kev && detected),
// unconfirmed otherwise.
func Match(inventory []Dependency, advisories []Advisory, kev map[string]KEVEntry, findings []FindingRef) []Hit {
	out := make([]Hit, 0, len(advisories))
	for _, adv := range advisories {
		kevHit := IsKEV(adv.CVEID, adv.Aliases, kev)
		matchedInventory := false
		for _, dep := range inventory {
			if !depMatchesAdvisory(dep, adv.AffectedPackages) {
				continue
			}
			matchedInventory = true
			finding, detected := matchFinding(dep, adv, findings)
			out = append(out, buildHit(adv, dep.Name, dep.Version, kevHit, true, detected, finding, dep))
		}
		if matchedInventory {
			continue
		}
		for _, f := range findings {
			if !findingMatchesAdvisoryCVE(f, adv) {
				continue
			}
			out = append(out, buildHit(adv, f.PkgName, f.PkgVersion, kevHit, false, true, f, Dependency{}))
		}
	}
	return out
}

// depMatchesAdvisory reports whether dep hits any affected package entry on
// normalized ecosystem plus lowercase name.
func depMatchesAdvisory(dep Dependency, affected []AffectedPackage) bool {
	eco := OSVEcosystem(dep.Ecosystem)
	if eco == "" {
		return false
	}
	name := strings.ToLower(dep.Name)
	if name == "" {
		return false
	}
	for _, ap := range affected {
		if !strings.EqualFold(ap.Ecosystem, eco) {
			continue
		}
		if strings.ToLower(ap.Name) == name {
			return true
		}
	}
	return false
}

// matchFinding reports whether any finding corroborates the (dep, advisory)
// pair: by CVEID/alias against the advisory, or by package name+version
// against the inventory row.
func matchFinding(dep Dependency, adv Advisory, findings []FindingRef) (FindingRef, bool) {
	for _, f := range findings {
		if findingMatchesAdvisoryCVE(f, adv) {
			return f, true
		}
		if f.PkgName != "" && f.PkgVersion != "" &&
			strings.ToLower(f.PkgName) == strings.ToLower(dep.Name) &&
			f.PkgVersion == dep.Version {
			return f, true
		}
	}
	return FindingRef{}, false
}

// findingMatchesAdvisoryCVE reports whether a finding references the advisory
// by CVE ID or alias.
func findingMatchesAdvisoryCVE(f FindingRef, adv Advisory) bool {
	if f.CVEID == "" {
		return false
	}
	if f.CVEID == adv.CVEID {
		return true
	}
	for _, alias := range adv.Aliases {
		if f.CVEID == alias {
			return true
		}
	}
	return false
}

// buildHit assembles one Hit with its evidence map and verdicts.
func buildHit(adv Advisory, pkgName, pkgVersion string, kevHit, declared, detected bool, finding FindingRef, dep Dependency) Hit {
	evidence := make(map[string]any, 3)
	if declared {
		evidence[StatusDeclared] = map[string]any{
			"ecosystem":   dep.Ecosystem,
			"name":        dep.Name,
			"version":     dep.Version,
			"source_file": dep.SourceFile,
		}
	}
	if detected {
		evidence[StatusDetected] = map[string]any{
			"finding_id": finding.ID,
			"package":    finding.PkgName,
			"version":    finding.PkgVersion,
			"cve_id":     finding.CVEID,
		}
	}

	var status string
	switch {
	case declared && detected:
		status = StatusCorroborated
	case detected:
		status = StatusDetected
	default:
		status = StatusDeclared
	}
	if status == StatusCorroborated {
		evidence[StatusCorroborated] = true
	}

	var matchStatus string
	switch {
	case status == StatusCorroborated:
		matchStatus = MatchActiveThreat
	case kevHit && status == StatusDetected:
		matchStatus = MatchActiveThreat
	default:
		matchStatus = MatchUnconfirmed
	}

	return Hit{
		AdvisoryID:      adv.AdvisoryID,
		CVEID:           adv.CVEID,
		PkgName:         pkgName,
		PkgVersion:      pkgVersion,
		InventoryStatus: status,
		KEV:             kevHit,
		MatchStatus:     matchStatus,
		Evidence:        evidence,
	}
}
