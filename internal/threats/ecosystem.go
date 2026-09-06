package threats

// osvEcosystems maps internal ecosystem identifiers to their canonical OSV
// ecosystem names. Case is significant for OSV queries: "PyPI" is capitalized
// while "crates.io" is lowercase.
var osvEcosystems = map[string]string{
	"npm":   "npm",
	"go":    "Go",
	"pip":   "PyPI",
	"cargo": "crates.io",
}

// OSVEcosystem returns the canonical OSV ecosystem name for an internal
// ecosystem identifier, or "" when the ecosystem has no OSV mapping.
func OSVEcosystem(ecosystem string) string {
	return osvEcosystems[ecosystem]
}
