package summarymeta

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
)

type Metadata struct {
	Fingerprint string
	IssueType   string
	RawExcerpt  string
}

func Build(scanner, ruleID, title string, raw []byte) Metadata {
	issueType := extractIssueType(scanner, raw)
	parts := []string{
		normalizeField(scanner),
		normalizeField(ruleID),
		normalizeField(title),
		normalizeField(issueType),
	}
	hash := sha256.Sum256([]byte(strings.Join(parts, "\n")))

	rawExcerpt := strings.TrimSpace(string(raw))
	if len(rawExcerpt) > 1200 {
		rawExcerpt = rawExcerpt[:1200]
	}

	return Metadata{
		Fingerprint: hex.EncodeToString(hash[:]),
		IssueType:   issueType,
		RawExcerpt:  rawExcerpt,
	}
}

func normalizeField(value string) string {
	return strings.ToLower(strings.Join(strings.Fields(strings.TrimSpace(value)), " "))
}

func extractIssueType(scanner string, raw []byte) string {
	if strings.ToLower(strings.TrimSpace(scanner)) != "kics" || len(raw) == 0 {
		return ""
	}

	var payload struct {
		Files []struct {
			IssueType string `json:"issue_type"`
		} `json:"files"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return ""
	}
	if len(payload.Files) == 0 {
		return ""
	}
	return strings.TrimSpace(payload.Files[0].IssueType)
}
