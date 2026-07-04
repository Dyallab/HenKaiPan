package scanner

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var (
	cweRe = regexp.MustCompile(`(?i)CWE-(\d+)`)
	cveRe = regexp.MustCompile(`(?i)CVE-\d{4}-\d+`)
)

func firstCWE(tags []string) string {
	for _, t := range tags {
		if m := cweRe.FindString(t); m != "" {
			return strings.ToUpper(m)
		}
	}
	return ""
}

func firstCVE(candidates ...string) string {
	for _, s := range candidates {
		if m := cveRe.FindString(s); m != "" {
			return strings.ToUpper(m)
		}
	}
	return ""
}

// cvssToSeverity converts a CVSS numeric score string to severity label.
func cvssToSeverity(score string) string {
	v, err := strconv.ParseFloat(score, 64)
	if err != nil {
		return ""
	}
	switch {
	case v >= 9.0:
		return "critical"
	case v >= 7.0:
		return "high"
	case v >= 4.0:
		return "medium"
	case v > 0:
		return "low"
	default:
		return "info"
	}
}

// parseTrivyMessage extracts structured fields from trivy's SARIF message text.
// Format: "Package: NAME\nInstalled Version: VER\nVulnerability CVE-...\nSeverity: HIGH\nFixed Version: VER\n..."
func parseTrivyMessage(msg string) (pkg, installedVer, fixedVer, severity string) {
	for _, line := range strings.Split(msg, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "Package: "):
			pkg = strings.TrimPrefix(line, "Package: ")
		case strings.HasPrefix(line, "Installed Version: "):
			installedVer = strings.TrimPrefix(line, "Installed Version: ")
		case strings.HasPrefix(line, "Fixed Version: "):
			fixedVer = strings.TrimPrefix(line, "Fixed Version: ")
		case strings.HasPrefix(line, "Severity: "):
			severity = strings.ToLower(strings.TrimPrefix(line, "Severity: "))
		}
	}
	return
}

// ── SARIF ────────────────────────────────────────────────────────────────────

type sarifDoc struct {
	Runs []struct {
		Tool struct {
			Driver struct {
				Rules []struct {
					ID               string `json:"id"`
					ShortDescription struct {
						Text string `json:"text"`
					} `json:"shortDescription"`
					FullDescription struct {
						Text string `json:"text"`
					} `json:"fullDescription"`
					Properties struct {
						Tags             []string `json:"tags"`
						CWE              []string `json:"cwe"`
						SecuritySeverity string   `json:"security-severity"`
					} `json:"properties"`
				} `json:"rules"`
			} `json:"driver"`
		} `json:"tool"`
		Results []struct {
			RuleID  string `json:"ruleId"`
			Message struct {
				Text string `json:"text"`
			} `json:"message"`
			Level     string `json:"level"`
			Locations []struct {
				PhysicalLocation struct {
					ArtifactLocation struct {
						URI string `json:"uri"`
					} `json:"artifactLocation"`
					Region struct {
						StartLine int `json:"startLine"`
						EndLine   int `json:"endLine"`
						Snippet   struct {
							Text string `json:"text"`
						} `json:"snippet"`
					} `json:"region"`
				} `json:"physicalLocation"`
			} `json:"locations"`
		} `json:"results"`
	} `json:"runs"`
}

func sarifLevel(l string) string {
	switch strings.ToLower(l) {
	case "error":
		return "high"
	case "warning":
		return "medium"
	case "note", "info":
		return "low"
	default:
		return "info"
	}
}

func ParseSARIF(data []byte) ([]FindingRow, error) {
	var doc sarifDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("sarif parse: %w", err)
	}
	var rows []FindingRow
	for _, run := range doc.Runs {
		type ruleInfo struct {
			shortDesc string
			fullDesc  string
			cwe       string
			cvss      string
		}
		ruleMap := map[string]ruleInfo{}
		for _, rule := range run.Tool.Driver.Rules {
			cwe := firstCWE(append(rule.Properties.Tags, rule.Properties.CWE...))
			ruleMap[rule.ID] = ruleInfo{
				shortDesc: rule.ShortDescription.Text,
				fullDesc:  rule.FullDescription.Text,
				cwe:       cwe,
				cvss:      rule.Properties.SecuritySeverity,
			}
		}

		for _, r := range run.Results {
			info := ruleMap[r.RuleID]

			// Base severity: SARIF level, override with CVSS if present.
			sev := sarifLevel(r.Level)
			if s := cvssToSeverity(info.cvss); s != "" {
				sev = s
			}

			row := FindingRow{
				RuleID:   r.RuleID,
				Severity: sev,
				CWEID:    info.cwe,
			}

			if cveRe.MatchString(r.RuleID) {
				// CVE finding (trivy, trivy-image): message is structured text.
				pkg, ver, fixed, msgSev := parseTrivyMessage(r.Message.Text)
				if msgSev != "" {
					row.Severity = msgSev
				}
				row.CVEID = strings.ToUpper(r.RuleID)
				if pkg != "" {
					if ver != "" {
						row.Title = fmt.Sprintf("%s in %s@%s", r.RuleID, pkg, ver)
					} else {
						row.Title = fmt.Sprintf("%s in %s", r.RuleID, pkg)
					}
				} else {
					row.Title = r.RuleID
				}
				// Description: fixed version hint + original message
				if fixed != "" && fixed != "N/A" && fixed != "" {
					row.Description = fmt.Sprintf("Fixed in: %s\n%s", fixed, r.Message.Text)
				} else {
					row.Description = r.Message.Text
				}
			} else {
				// SAST/IaC finding: message text is the finding description.
				msg := r.Message.Text
				if msg == "" {
					msg = info.shortDesc
				}
				if msg == "" {
					msg = r.RuleID
				}
				if len(msg) > 120 {
					row.Title = msg[:120] + "…"
					row.Description = msg
				} else {
					row.Title = msg
					// Use fullDesc as description if available and different from title
					if info.fullDesc != "" && info.fullDesc != msg {
						row.Description = info.fullDesc
					}
				}
			}

			if len(r.Locations) > 0 {
				loc := r.Locations[0].PhysicalLocation
				row.FilePath = strings.TrimPrefix(loc.ArtifactLocation.URI, "file:///src/")
				row.LineStart = loc.Region.StartLine
				row.LineEnd = loc.Region.EndLine
				row.CodeSnippet = loc.Region.Snippet.Text
			}
			raw, _ := json.Marshal(r)
			row.Raw = raw
			rows = append(rows, row)
		}
	}
	return rows, nil
}

// ── Grype ────────────────────────────────────────────────────────────────────

type grypeDoc struct {
	Matches []struct {
		Vulnerability struct {
			ID          string   `json:"id"`
			Severity    string   `json:"severity"`
			Description string   `json:"description"`
			URLs        []string `json:"urls"`
		} `json:"vulnerability"`
		RelatedVulnerabilities []struct {
			ID string `json:"id"`
		} `json:"relatedVulnerabilities"`
		Artifact struct {
			Name      string `json:"name"`
			Version   string `json:"version"`
			Type      string `json:"type"`
			Locations []struct {
				RealPath string `json:"realPath"`
			} `json:"locations"`
		} `json:"artifact"`
	} `json:"matches"`
}

func normalizeGrype(s string) string {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return "critical"
	case "HIGH":
		return "high"
	case "MEDIUM":
		return "medium"
	case "LOW":
		return "low"
	default:
		return "info"
	}
}

func ParseGrype(data []byte) ([]FindingRow, error) {
	var doc grypeDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("grype parse: %w", err)
	}
	var rows []FindingRow
	for _, m := range doc.Matches {
		fp := ""
		if len(m.Artifact.Locations) > 0 {
			fp = m.Artifact.Locations[0].RealPath
		}
		title := m.Vulnerability.ID
		if m.Artifact.Name != "" {
			title = fmt.Sprintf("%s in %s@%s", m.Vulnerability.ID, m.Artifact.Name, m.Artifact.Version)
		}

		// CVE: id itself is CVE or GHSA; also check related
		vulnID := m.Vulnerability.ID
		cve := firstCVE(vulnID)
		if cve == "" {
			for _, rv := range m.RelatedVulnerabilities {
				if c := firstCVE(rv.ID); c != "" {
					cve = c
					break
				}
			}
		}

		raw, _ := json.Marshal(m)
		rows = append(rows, FindingRow{
			RuleID:      vulnID,
			Title:       title,
			Description: m.Vulnerability.Description,
			Severity:    normalizeGrype(m.Vulnerability.Severity),
			FilePath:    fp,
			Raw:         raw,
			CVEID:       cve,
		})
	}
	return rows, nil
}

// ── OSV-Scanner ──────────────────────────────────────────────────────────────

type osvDoc struct {
	Results []struct {
		Source struct {
			Path string `json:"path"`
		} `json:"source"`
		Packages []struct {
			Package struct {
				Name      string `json:"name"`
				Version   string `json:"version"`
				Ecosystem string `json:"ecosystem"`
			} `json:"package"`
			Vulnerabilities []struct {
				ID      string   `json:"id"`
				Aliases []string `json:"aliases"`
				Summary string   `json:"summary"`
				Details string   `json:"details"`
				DatabaseSpecific struct {
					Severity string   `json:"severity"`
					CWEIDs   []string `json:"cwe_ids"`
				} `json:"database_specific"`
			} `json:"vulnerabilities"`
		} `json:"packages"`
	} `json:"results"`
}

func ParseOSV(data []byte) ([]FindingRow, error) {
	var doc osvDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("osv parse: %w", err)
	}
	var rows []FindingRow
	for _, res := range doc.Results {
		for _, pkg := range res.Packages {
			for _, v := range pkg.Vulnerabilities {
				sev := strings.ToLower(v.DatabaseSpecific.Severity)
				if sev == "" {
					sev = "medium"
				}
				title := v.Summary
				if title == "" {
					title = v.ID
				}

				// CVE: id itself or first CVE alias
				cve := firstCVE(v.ID)
				if cve == "" {
					for _, a := range v.Aliases {
						if c := firstCVE(a); c != "" {
							cve = c
							break
						}
					}
				}
				// CWE: from database_specific
				cwe := firstCWE(v.DatabaseSpecific.CWEIDs)

				raw, _ := json.Marshal(v)
				rows = append(rows, FindingRow{
					RuleID:      v.ID,
					Title:       fmt.Sprintf("%s in %s@%s", v.ID, pkg.Package.Name, pkg.Package.Version),
					Description: title,
					Severity:    sev,
					FilePath:    res.Source.Path,
					Raw:         raw,
					CVEID:       cve,
					CWEID:       cwe,
				})
			}
		}
	}
	return rows, nil
}

// ── Trufflehog ───────────────────────────────────────────────────────────────

type thogLine struct {
	SourceMetadata struct {
		Data struct {
			Git struct {
				File   string `json:"file"`
				Line   int    `json:"line"`
				Commit string `json:"commit"`
			} `json:"Git"`
		} `json:"Data"`
	} `json:"SourceMetadata"`
	Raw          string `json:"Raw"`
	DetectorName string `json:"DetectorName"`
	Verified     bool   `json:"Verified"`
}

func ParseTrufflehog(data []byte) ([]FindingRow, error) {
	var rows []FindingRow
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := sc.Bytes()
		var r thogLine
		if err := json.Unmarshal(line, &r); err != nil {
			continue
		}
		sev := "high"
		if r.Verified {
			sev = "critical"
		}
		raw, _ := json.Marshal(r)
		rows = append(rows, FindingRow{
			RuleID:      r.DetectorName,
			Title:       fmt.Sprintf("%s secret detected", r.DetectorName),
			Description: fmt.Sprintf("Verified: %v", r.Verified),
			Severity:    sev,
			FilePath:    r.SourceMetadata.Data.Git.File,
			LineStart:   r.SourceMetadata.Data.Git.Line,
			Raw:         raw,
		})
	}
	return rows, nil
}

// ── Gitleaks ─────────────────────────────────────────────────────────────────

type gitleaksDoc []struct {
	Description string  `json:"Description"`
	StartLine   int     `json:"StartLine"`
	EndLine     int     `json:"EndLine"`
	Match       string  `json:"Match"`
	File        string  `json:"File"`
	Entropy     float64 `json:"Entropy"`
	RuleID      string  `json:"RuleID"`
	Commit      string  `json:"Commit"`
}

func ParseGitleaks(data []byte) ([]FindingRow, error) {
	var doc gitleaksDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		// gitleaks may return null when no leaks
		return nil, nil
	}
	var rows []FindingRow
	for _, l := range doc {
		raw, _ := json.Marshal(l)
		rows = append(rows, FindingRow{
			RuleID:    l.RuleID,
			Title:     l.Description,
			Severity:  "high",
			FilePath:  l.File,
			LineStart: l.StartLine,
			LineEnd:   l.EndLine,
			Raw:       raw,
		})
	}
	return rows, nil
}

// ── Checkov ──────────────────────────────────────────────────────────────────

type checkovCheck struct {
	CheckID       string   `json:"check_id"`
	CheckResult   struct{} `json:"check_result"`
	FilePath      string   `json:"file_path"`
	FileLineRange [2]int   `json:"file_line_range"`
	Resource      string   `json:"resource"`
	Severity      string   `json:"severity"`
	Check         struct {
		Name string `json:"name"`
	} `json:"check"`
}

type checkovDoc struct {
	Results struct {
		FailedChecks []checkovCheck `json:"failed_checks"`
	} `json:"results"`
}

func normalizeCheckov(s string) string {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return "critical"
	case "HIGH":
		return "high"
	case "MEDIUM":
		return "medium"
	case "LOW":
		return "low"
	default:
		return "medium"
	}
}

func ParseCheckov(data []byte) ([]FindingRow, error) {
	trimmed := bytes.TrimSpace(data)

	var checks []checkovCheck

	if bytes.HasPrefix(trimmed, []byte("[")) {
		var docs []checkovDoc
		if err := json.Unmarshal(trimmed, &docs); err == nil {
			for _, d := range docs {
				checks = append(checks, d.Results.FailedChecks...)
			}
		}
	} else {
		var doc checkovDoc
		if err := json.Unmarshal(trimmed, &doc); err != nil {
			return nil, fmt.Errorf("checkov parse: %w", err)
		}
		checks = doc.Results.FailedChecks
	}

	var rows []FindingRow
	for _, c := range checks {
		title := c.Check.Name
		if title == "" {
			title = c.CheckID
		}
		raw, _ := json.Marshal(c)
		rows = append(rows, FindingRow{
			RuleID:    c.CheckID,
			Title:     title,
			Severity:  normalizeCheckov(c.Severity),
			FilePath:  c.FilePath,
			LineStart: c.FileLineRange[0],
			LineEnd:   c.FileLineRange[1],
			Raw:       raw,
		})
	}
	return rows, nil
}

// ── KICS ─────────────────────────────────────────────────────────────────────

type kicsDoc struct {
	Queries []struct {
		QueryID   string `json:"query_id"`
		QueryName string `json:"query_name"`
		Severity  string `json:"severity"`
		Files     []struct {
			FileName  string `json:"file_name"`
			Line      int    `json:"line"`
			IssueType string `json:"issue_type"`
		} `json:"files"`
	} `json:"queries"`
}

func ParseKICS(data []byte) ([]FindingRow, error) {
	var doc kicsDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("kics parse: %w", err)
	}
	var rows []FindingRow
	for _, q := range doc.Queries {
		sev := strings.ToLower(q.Severity)
		for _, f := range q.Files {
			raw, _ := json.Marshal(q)
			rows = append(rows, FindingRow{
				RuleID:    q.QueryID,
				Title:     q.QueryName,
				Severity:  sev,
				FilePath:  f.FileName,
				LineStart: f.Line,
				Raw:       raw,
			})
		}
	}
	return rows, nil
}

// ── Nuclei ───────────────────────────────────────────────────────────────────

type nucleiLine struct {
	TemplateID string `json:"template-id"`
	Info       struct {
		Name        string `json:"name"`
		Severity    string `json:"severity"`
		Description string `json:"description"`
		Classification struct {
			CVEIDs []string `json:"cve-id"`
			CWEIDs []string `json:"cwe-id"`
		} `json:"classification"`
	} `json:"info"`
	Host      string `json:"host"`
	MatchedAt string `json:"matched-at"`
}

func ParseNuclei(data []byte) ([]FindingRow, error) {
	var rows []FindingRow
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := sc.Bytes()
		var r nucleiLine
		if err := json.Unmarshal(line, &r); err != nil {
			continue
		}
		cve := ""
		if len(r.Info.Classification.CVEIDs) > 0 {
			cve = strings.ToUpper(r.Info.Classification.CVEIDs[0])
		}
		cwe := firstCWE(r.Info.Classification.CWEIDs)

		raw, _ := json.Marshal(r)
		rows = append(rows, FindingRow{
			RuleID:      r.TemplateID,
			Title:       r.Info.Name,
			Description: r.Info.Description,
			Severity:    strings.ToLower(r.Info.Severity),
			FilePath:    r.MatchedAt,
			Raw:         raw,
			CVEID:       cve,
			CWEID:       cwe,
		})
	}
	return rows, nil
}
