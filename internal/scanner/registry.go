package scanner

import "fmt"

type Category = string
type TargetType = string
type OutputFormat = string

const (
	CategorySAST       Category = "sast"
	CategorySCA        Category = "sca"
	CategorySecrets    Category = "secrets"
	CategoryIaC        Category = "iac"
	CategoryContainers Category = "containers"
	CategoryDAST       Category = "dast"

	TargetGit TargetType = "git"
	TargetURL TargetType = "url"

	FormatJSON  OutputFormat = "json"
	FormatJSONL OutputFormat = "jsonlines"
	FormatSARIF OutputFormat = "sarif"
)

// FindingRow is the normalized output every parser must produce.
type FindingRow struct {
	RuleID      string
	Title       string
	Description string
	Severity    string
	FilePath    string
	LineStart   int
	LineEnd     int
	CodeSnippet string
	Raw         []byte
	CVEID       string // e.g. "CVE-2021-44228"
	CWEID       string // e.g. "CWE-89"
	SecretHash  string // SHA256 hash of detected secret value (for trufflehog/gitleaks correlation)
}

type ParserFunc func(output []byte) ([]FindingRow, error)

// Scanner defines everything the generic worker needs to run a scan.
type Scanner struct {
	Name        string
	Category    Category
	Description string
	Image       string
	// BuildArgs receives the effective target (mount dst for git, URL for dast).
	BuildArgs    func(target string) []string
	WorkDir      string            // container working directory, empty = default
	MountDst     string            // where the cloned repo is mounted inside the container
	Entrypoint   []string          // override container ENTRYPOINT (--entrypoint)
	Env          map[string]string // extra env vars passed to docker run (-e KEY=VAL)
	ExtraVolumes []string          // extra volume mounts ("host:container")
	Format       OutputFormat
	TargetType   TargetType
	Parse        ParserFunc
}

// Info is the serialisable, public view of a Scanner.
type Info struct {
	Name        string `json:"name"`
	Category    string `json:"category"`
	Description string `json:"description"`
	TargetType  string `json:"target_type"`
}

var Registry = map[string]Scanner{
	// ── SAST ─────────────────────────────────────────────────────────────────

	// semgrep/semgrep:latest uses CMD (no ENTRYPOINT), so "semgrep" must be the first arg.
	"semgrep": {
		Name:        "semgrep",
		Category:    CategorySAST,
		Description: "Static analysis for 30+ languages",
		Image:       "semgrep/semgrep:latest",
		MountDst:    "/src",
		BuildArgs: func(t string) []string {
			return []string{"semgrep", "--sarif", "--config=auto", "--no-rewrite-rule-ids", t}
		},
		Format:     FormatSARIF,
		TargetType: TargetGit,
		Parse:      ParseSARIF,
	},
	// gosec entrypoint is "gosec"; WorkDir must be set so ./... resolves correctly.
	"gosec": {
		Name:        "gosec",
		Category:    CategorySAST,
		Description: "Go security checker (Go projects only)",
		Image:       "securego/gosec:latest",
		MountDst:    "/src",
		WorkDir:     "/src",
		BuildArgs: func(_ string) []string {
			return []string{"-fmt=sarif", "-stdout", "./..."}
		},
		Format:     FormatSARIF,
		TargetType: TargetGit,
		Parse:      ParseSARIF,
	},

	// ── SCA ──────────────────────────────────────────────────────────────────

	// Trivy downloads its vuln DB on first run via HTTPS. In environments with
	// TLS inspection (corporate proxy) the cert verification fails. TRIVY_INSECURE
	// skips TLS for all trivy HTTP calls. Cache persists on the host at /tmp/trivy-cache.
	"trivy": {
		Name:         "trivy",
		Category:     CategorySCA,
		Description:  "Vulnerability scanner for packages and containers",
		Image:        "aquasec/trivy:latest",
		MountDst:     "/src",
		Env:          map[string]string{"TRIVY_INSECURE": "true"},
		ExtraVolumes: []string{"/tmp/trivy-cache:/root/.cache/trivy"},
		BuildArgs: func(t string) []string {
			return []string{"fs", "--format", "sarif", "--exit-code", "0", "--no-progress", t}
		},
		Format:     FormatSARIF,
		TargetType: TargetGit,
		Parse:      ParseSARIF,
	},
	"grype": {
		Name:         "grype",
		Category:     CategorySCA,
		Description:  "Vulnerability scanner for filesystems (Anchore)",
		Image:        "anchore/grype:latest",
		MountDst:     "/src",
		Env:          map[string]string{"GRYPE_DB_AUTO_UPDATE": "true"},
		ExtraVolumes: []string{"/tmp/grype-cache:/root/.cache/grype"},
		BuildArgs: func(t string) []string {
			return []string{fmt.Sprintf("dir:%s", t), "-o", "json"}
		},
		Format:     FormatJSON,
		TargetType: TargetGit,
		Parse:      ParseGrype,
	},
	"osv-scanner": {
		Name:        "osv-scanner",
		Category:    CategorySCA,
		Description: "Open Source Vulnerabilities scanner (Google)",
		Image:       "ghcr.io/google/osv-scanner:latest",
		MountDst:    "/src",
		BuildArgs: func(t string) []string {
			return []string{"--format", "json", "-r", t}
		},
		Format:     FormatJSON,
		TargetType: TargetGit,
		Parse:      ParseOSV,
	},

	// ── Secrets ──────────────────────────────────────────────────────────────
	"trufflehog": {
		Name:        "trufflehog",
		Category:    CategorySecrets,
		Description: "Detect secrets in git history",
		Image:       "trufflesecurity/trufflehog:latest",
		MountDst:    "/repo",
		BuildArgs: func(t string) []string {
			return []string{"git", "--json", "--no-update", fmt.Sprintf("file://%s", t)}
		},
		Format:     FormatJSONL,
		TargetType: TargetGit,
		Parse:      ParseTrufflehog,
	},
	"gitleaks": {
		Name:        "gitleaks",
		Category:    CategorySecrets,
		Description: "Detect hardcoded secrets in git repos",
		Image:       "zricethezav/gitleaks:latest",
		MountDst:    "/repo",
		BuildArgs: func(t string) []string {
			return []string{"detect", "--source", t, "--report-format", "json", "--exit-code", "0"}
		},
		Format:     FormatJSON,
		TargetType: TargetGit,
		Parse:      ParseGitleaks,
	},

	// ── IaC ──────────────────────────────────────────────────────────────────
	"checkov": {
		Name:        "checkov",
		Category:    CategoryIaC,
		Description: "IaC security analysis (Terraform, K8s, Dockerfile, ARM…)",
		Image:       "bridgecrew/checkov:latest",
		MountDst:    "/tf",
		BuildArgs: func(t string) []string {
			return []string{"-d", t, "-o", "json", "--compact"}
		},
		Format:     FormatJSON,
		TargetType: TargetGit,
		Parse:      ParseCheckov,
	},
	// tfsec entrypoint is "tfsec".
	"tfsec": {
		Name:        "tfsec",
		Category:    CategoryIaC,
		Description: "Terraform security scanner",
		Image:       "aquasec/tfsec:latest",
		MountDst:    "/src",
		BuildArgs: func(t string) []string {
			return []string{"--format", "sarif", "--no-color", t}
		},
		Format:     FormatSARIF,
		TargetType: TargetGit,
		Parse:      ParseSARIF,
	},
	// kics writes JSON to a file and logs to stdout; --silent suppresses logs,
	// then we cat the results file so stdout is pure JSON for the parser.
	"kics": {
		Name:        "kics",
		Category:    CategoryIaC,
		Description: "IaC security analysis for 20+ platforms (Checkmarx)",
		Image:       "checkmarx/kics:latest",
		MountDst:    "/path",
		Entrypoint:  []string{"/bin/sh"},
		BuildArgs: func(t string) []string {
			return []string{"-c", fmt.Sprintf("kics scan -p %s --report-formats json --silent -o /tmp/kicsout; cat /tmp/kicsout/results.json 2>/dev/null || echo '{\"queries\":[]}'", t)}
		},
		Format:     FormatJSON,
		TargetType: TargetGit,
		Parse:      ParseKICS,
	},

	// ── Containers ───────────────────────────────────────────────────────────
	// Target = container image ref (e.g. nginx:latest), NOT a git URL.
	"trivy-image": {
		Name:         "trivy-image",
		Category:     CategoryContainers,
		Description:  "Container image vulnerability scanner — target: image ref (e.g. nginx:latest)",
		Image:        "aquasec/trivy:latest",
		Env:          map[string]string{"TRIVY_INSECURE": "true"},
		ExtraVolumes: []string{"/tmp/trivy-cache:/root/.cache/trivy"},
		BuildArgs: func(t string) []string {
			return []string{"image", "--format", "sarif", "--exit-code", "0", "--no-progress", t}
		},
		Format:     FormatSARIF,
		TargetType: TargetURL,
		Parse:      ParseSARIF,
	},
	"grype-image": {
		Name:         "grype-image",
		Category:     CategoryContainers,
		Description:  "Container image vulnerability scanner (Anchore) — target: image ref",
		Image:        "anchore/grype:latest",
		ExtraVolumes: []string{"/tmp/grype-cache:/root/.cache/grype"},
		BuildArgs: func(t string) []string {
			return []string{t, "-o", "json"}
		},
		Format:     FormatJSON,
		TargetType: TargetURL,
		Parse:      ParseGrype,
	},

	// ── DAST ─────────────────────────────────────────────────────────────────
	// Target = web URL (e.g. https://app.example.com), NOT a git repo.
	"nuclei": {
		Name:        "nuclei",
		Category:    CategoryDAST,
		Description: "Template-based web vulnerability scanner — target: web URL",
		Image:       "projectdiscovery/nuclei:latest",
		BuildArgs: func(t string) []string {
			return []string{"-u", t, "-jsonl", "-silent", "-no-color"}
		},
		Format:     FormatJSONL,
		TargetType: TargetURL,
		Parse:      ParseNuclei,
	},
}

func Get(name string) (Scanner, bool) {
	s, ok := Registry[name]
	return s, ok
}

func CategoryFor(name string) (Category, bool) {
	s, ok := Registry[name]
	if !ok {
		return "", false
	}
	return s.Category, true
}

func SameCategory(a, b string) bool {
	ac, ok := CategoryFor(a)
	if !ok {
		return false
	}
	bc, ok := CategoryFor(b)
	if !ok {
		return false
	}
	return ac == bc
}

func ListInfo() []Info {
	out := make([]Info, 0, len(Registry))
	for _, s := range Registry {
		out = append(out, Info{
			Name:        s.Name,
			Category:    s.Category,
			Description: s.Description,
			TargetType:  s.TargetType,
		})
	}
	return out
}

// GitScannerNames returns all scanners that operate on a cloned git repo.
func GitScannerNames() []string {
	var names []string
	for name, s := range Registry {
		if s.TargetType == TargetGit {
			names = append(names, name)
		}
	}
	return names
}
