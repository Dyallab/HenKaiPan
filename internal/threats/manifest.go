package threats

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"path"
	"sort"
	"strings"
)

// Dependency is a single (ecosystem, name, version) row parsed from a
// manifest or lockfile. SourceFile records which manifest produced the row.
type Dependency struct {
	Ecosystem  string
	Name       string
	Version    string
	SourceFile string
}

// ParseManifest parses package.json, go.mod, requirements.txt, or Cargo.lock
// content into dependency rows. sourceFile selects the parser by base name.
// It returns an error on malformed input and never panics.
//
// Version ranges that cannot be resolved to a single installed version
// (npm semver ranges, unpinned pip specifiers, go indirect requirements)
// are skipped rather than guessed at.
func ParseManifest(sourceFile string, data []byte) ([]Dependency, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, fmt.Errorf("threats: empty manifest %q", sourceFile)
	}
	var deps []Dependency
	var err error
	switch base := path.Base(sourceFile); {
	case base == "package.json":
		deps, err = parsePackageJSON(sourceFile, data)
	case base == "go.mod":
		deps, err = parseGoMod(sourceFile, data)
	case base == "Cargo.lock":
		deps, err = parseCargoLock(sourceFile, data)
	case base == "requirements.txt" ||
		(strings.HasPrefix(base, "requirements") && strings.HasSuffix(base, ".txt")):
		deps, err = parseRequirementsTxt(sourceFile, data)
	default:
		return nil, fmt.Errorf("threats: unsupported manifest %q", sourceFile)
	}
	if err != nil {
		return nil, err
	}
	sort.Slice(deps, func(i, j int) bool {
		if deps[i].Name != deps[j].Name {
			return deps[i].Name < deps[j].Name
		}
		return deps[i].Version < deps[j].Version
	})
	return deps, nil
}

func parsePackageJSON(sourceFile string, data []byte) ([]Dependency, error) {
	var pkg struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil, fmt.Errorf("threats: parse package.json: %w", err)
	}
	var deps []Dependency
	for _, scope := range []map[string]string{pkg.Dependencies, pkg.DevDependencies} {
		for name, spec := range scope {
			// devDependencies entries are resolved to their installed
			// version, not the declared range: only the base version is
			// kept, complex ranges are skipped (see resolveNPMVersion).
			version, ok := resolveNPMVersion(spec)
			if !ok {
				continue
			}
			deps = append(deps, Dependency{
				Ecosystem:  "npm",
				Name:       name,
				Version:    version,
				SourceFile: sourceFile,
			})
		}
	}
	return deps, nil
}

// resolveNPMVersion strips a leading ^, ~, =, or v prefix to recover the
// installed version from a declared range. Multi-part ranges ("a b",
// "a,b", "a||b") and open-ended comparators (>, <, *, latest, URLs,
// aliases) cannot be resolved to one version and are skipped.
func resolveNPMVersion(spec string) (string, bool) {
	s := strings.TrimSpace(spec)
	if s == "" || s == "*" || s == "latest" {
		return "", false
	}
	if strings.ContainsAny(s, " ,|") {
		return "", false
	}
	s = strings.TrimLeft(s, "^~=")
	s = strings.TrimPrefix(s, "v")
	if s == "" {
		return "", false
	}
	if c := s[0]; c < '0' || c > '9' {
		// Comparators (>, <, !), URLs, aliases, and dist-tags carry
		// no single registry version.
		return "", false
	}
	return s, true
}

func parseGoMod(sourceFile string, data []byte) ([]Dependency, error) {
	var deps []Dependency
	inRequire := false
	closedRequire := true
	sawModule := false
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if idx := strings.Index(line, "//"); idx >= 0 {
			comment := line[idx:]
			line = strings.TrimSpace(line[:idx])
			// Indirect requirements are skipped: only direct
			// dependencies are reported as first-party rows.
			if strings.Contains(comment, "indirect") {
				continue
			}
		}
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "module ") {
			sawModule = true
			continue
		}
		if line == "require (" || line == "require(" {
			inRequire = true
			closedRequire = false
			continue
		}
		if inRequire && line == ")" {
			inRequire = false
			closedRequire = true
			continue
		}
		require, rest, ok := strings.Cut(line, "require ")
		if ok && strings.TrimSpace(require) == "" {
			fields := strings.Fields(rest)
			if len(fields) < 2 {
				return nil, fmt.Errorf("threats: parse go.mod: bad require %q", line)
			}
			deps = append(deps, Dependency{
				Ecosystem:  "go",
				Name:       fields[0],
				Version:    fields[1],
				SourceFile: sourceFile,
			})
			continue
		}
		if !inRequire {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return nil, fmt.Errorf("threats: parse go.mod: bad require %q", line)
		}
		deps = append(deps, Dependency{
			Ecosystem:  "go",
			Name:       fields[0],
			Version:    fields[1],
			SourceFile: sourceFile,
		})
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("threats: parse go.mod: %w", err)
	}
	if inRequire || !closedRequire {
		return nil, fmt.Errorf("threats: parse go.mod: unclosed require block")
	}
	if !sawModule {
		return nil, fmt.Errorf("threats: parse go.mod: missing module directive")
	}
	return deps, nil
}

func parseRequirementsTxt(sourceFile string, data []byte) ([]Dependency, error) {
	var deps []Dependency
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}
		// Strip environment markers ("pkg==1.0 ; python_version > ...").
		if idx := strings.Index(line, ";"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		// Strip inline comments.
		if idx := strings.Index(line, "#"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		// Only pinned == specifiers resolve to one version; bare names
		// and open ranges (>=, ~=, !=, <, >) are skipped.
		name, version, ok := strings.Cut(line, "==")
		if !ok {
			continue
		}
		name = strings.TrimSpace(name)
		version = strings.TrimSpace(version)
		if idx := strings.IndexAny(version, ", \t"); idx >= 0 {
			version = strings.TrimSpace(version[:idx])
		}
		version = strings.Trim(version, `"'`)
		// Strip extras ("uvicorn[standard]" -> "uvicorn").
		if idx := strings.Index(name, "["); idx >= 0 {
			end := strings.Index(name[idx:], "]")
			if end < 0 {
				continue
			}
			name = strings.TrimSpace(name[:idx])
		}
		if name == "" || version == "" {
			continue
		}
		deps = append(deps, Dependency{
			Ecosystem:  "pip",
			Name:       strings.ToLower(name),
			Version:    version,
			SourceFile: sourceFile,
		})
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("threats: parse requirements.txt: %w", err)
	}
	return deps, nil
}

func parseCargoLock(sourceFile string, data []byte) ([]Dependency, error) {
	var deps []Dependency
	inPackage := false
	var name, version string
	flush := func() error {
		if !inPackage {
			return nil
		}
		if name == "" || version == "" {
			return fmt.Errorf("threats: parse Cargo.lock: incomplete [[package]] (name=%q version=%q)", name, version)
		}
		deps = append(deps, Dependency{
			Ecosystem:  "cargo",
			Name:       name,
			Version:    version,
			SourceFile: sourceFile,
		})
		name, version = "", ""
		return nil
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if line == "[[package]]" {
			if err := flush(); err != nil {
				return nil, err
			}
			inPackage = true
			name, version = "", ""
			continue
		}
		if !inPackage {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key != "name" && key != "version" {
			continue
		}
		unquoted, ok := unquoteTOML(value)
		if !ok {
			return nil, fmt.Errorf("threats: parse Cargo.lock: bad %s value %q", key, value)
		}
		if key == "name" {
			name = unquoted
		} else {
			version = unquoted
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("threats: parse Cargo.lock: %w", err)
	}
	if err := flush(); err != nil {
		return nil, err
	}
	if len(deps) == 0 {
		return nil, fmt.Errorf("threats: parse Cargo.lock: no [[package]] entries")
	}
	return deps, nil
}

func unquoteTOML(value string) (string, bool) {
	if len(value) >= 2 && strings.HasPrefix(value, `"`) && strings.HasSuffix(value, `"`) {
		return value[1 : len(value)-1], true
	}
	if len(value) >= 2 && strings.HasPrefix(value, `'`) && strings.HasSuffix(value, `'`) {
		return value[1 : len(value)-1], true
	}
	return "", false
}
