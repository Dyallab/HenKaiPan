// Package threats — inventory × advisory × KEV × findings matcher (issue #64).
//
// Match is a pure function: it joins manifest inventory rows against OSV
// advisories, flags KEV-listed CVEs, and corroborates hits with pre-existing
// scanner findings. It performs no DB or HTTP I/O.
package threats

import (
	"strconv"
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

// MatchQueryHits joins per-dependency OSV query hits (see QueryBatchWithDeps)
// against KEV and findings. Unlike Match — which joins advisories to
// inventory by package name only — each hit already knows the exact queried
// dependency version, so the advisory's affected ranges are verified before
// emitting: when the entries matching the dep carry introduced/fixed events,
// a dep outside every range yields no hit; when they carry no usable events,
// the OSV server match is trusted and the hit is kept.
func MatchQueryHits(hits []QueryHit, kev map[string]KEVEntry, findings []FindingRef) []Hit {
	out := make([]Hit, 0, len(hits))
	for _, h := range hits {
		if !depMatchesAdvisory(h.Dependency, h.Advisory.AffectedPackages) {
			continue
		}
		if !depInAffectedRanges(h.Dependency, h.Advisory.AffectedPackages) {
			continue
		}
		kevHit := IsKEV(h.Advisory.CVEID, h.Advisory.Aliases, kev)
		finding, detected := matchFinding(h.Dependency, h.Advisory, findings)
		out = append(out, buildHit(h.Advisory, h.Dependency.Name, h.Dependency.Version, kevHit, true, detected, finding, h.Dependency))
	}
	return out
}

// depInAffectedRanges reports whether dep.Version falls inside any affected
// range of the advisory entries matching the dep (normalized ecosystem plus
// lowercase name). Entries for other packages are ignored. When no matching
// entry carries usable introduced/fixed events, it returns true — the OSV
// server already matched this version and there is nothing local to check.
func depInAffectedRanges(dep Dependency, affected []AffectedPackage) bool {
	eco := OSVEcosystem(dep.Ecosystem)
	name := strings.ToLower(dep.Name)
	matched := false
	for _, ap := range affected {
		if !strings.EqualFold(ap.Ecosystem, eco) || strings.ToLower(ap.Name) != name {
			continue
		}
		matched = true
		for _, r := range ap.Ranges {
			if versionInEvents(dep.Version, r.Events) {
				return true
			}
		}
	}
	if !matched {
		return false
	}
	for _, ap := range affected {
		if !strings.EqualFold(ap.Ecosystem, eco) || strings.ToLower(ap.Name) != name {
			continue
		}
		for _, r := range ap.Ranges {
			if len(r.Events) > 0 {
				return false
			}
		}
	}
	return true
}

// versionInEvents walks OSV introduced/fixed events in order: introduced arms
// the range when the version reaches it, fixed disarms it once the version
// reaches the fix. A fixed-only event implies the range was armed from the
// start. An event list with no usable bounds returns true (trust OSV).
func versionInEvents(version string, events []RangeEvent) bool {
	affected := false
	bounded := false
	for _, e := range events {
		if e.Introduced != "" {
			bounded = true
			affected = compareVersions(version, e.Introduced) >= 0
		}
		if e.Fixed != "" {
			if !bounded {
				bounded = true
				affected = true
			}
			if affected && compareVersions(version, e.Fixed) >= 0 {
				affected = false
			}
		}
	}
	if !bounded {
		return true
	}
	return affected
}

// compareVersions orders versions by numeric segments, falling back to
// lexical order for non-numeric segments. It strips a leading "v" and build
// metadata ("+..."), splits on "."/"-"/"_", and treats missing trailing
// segments as zero, so "1.3" equals "1.3.0". This is an approximation for
// exact/prefix range checks, not full semver (no prerelease precedence,
// no ecosystem-specific schemes).
func compareVersions(a, b string) int {
	sa := splitVersion(a)
	sb := splitVersion(b)
	n := max(len(sa), len(sb))
	for i := 0; i < n; i++ {
		var x, y string
		if i < len(sa) {
			x = sa[i]
		} else {
			x = "0"
		}
		if i < len(sb) {
			y = sb[i]
		} else {
			y = "0"
		}
		xi, xerr := strconv.Atoi(x)
		yi, yerr := strconv.Atoi(y)
		switch {
		case xerr == nil && yerr == nil:
			if xi != yi {
				if xi < yi {
					return -1
				}
				return 1
			}
		case x == y:
		default:
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

func splitVersion(v string) []string {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "v")
	v = strings.TrimPrefix(v, "V")
	if i := strings.Index(v, "+"); i >= 0 {
		v = v[:i]
	}
	return strings.FieldsFunc(v, func(r rune) bool {
		return r == '.' || r == '-' || r == '_'
	})
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
