package testdb

import (
	"testing"

	"aspm/internal/assert"
)

// fkEdges mirrors the foreign keys between seed tables and their dependents
// (from internal/db/migrations). Each edge is [child, parent]: the child
// must be truncated before the parent.
var fkEdges = [][2]string{
	{"jira_issue_links", "findings"},
	{"agent_analyses", "findings"},
	{"finding_correlations", "findings"},
	{"finding_comments", "findings"},
	{"finding_comments", "users"},
	{"risk_acceptances", "findings"},
	{"risk_acceptances", "users"},
	{"findings", "scans"},
	{"findings", "projects"},
	{"scans", "projects"},
	{"vulnerabilities", "projects"},
	{"project_dependencies", "projects"},
	{"project_inventory_hits", "projects"},
	{"scan_schedules", "projects"},
	{"scan_schedules", "apps"},
	{"api_tokens", "projects"},
	{"api_tokens", "users"},
	{"projects", "apps"},
	{"apps", "teams"},
	{"team_members", "teams"},
	{"team_members", "users"},
	{"user_notifications", "users"},
}

// seedTablesFromSeedDemo are the tables scripts/seed-demo.sql writes to.
var seedTablesFromSeedDemo = []string{
	"teams", "users", "team_members", "apps", "projects", "scans", "findings",
}

func TestSeedTablesCoverSeedData(t *testing.T) {
	for _, table := range seedTablesFromSeedDemo {
		if !contains(seedTables, table) {
			t.Errorf("seed table %q missing from seedTables", table)
		}
	}
}

func TestSeedTablesExcludeSingletons(t *testing.T) {
	// Singletons are never truncated — Reset restores them instead.
	assert.False(t, contains(seedTables, "notification_settings"))
	assert.False(t, contains(seedTables, "jira_integrations"))
}

func TestSeedTablesFKOrder(t *testing.T) {
	for _, edge := range fkEdges {
		child, parent := edge[0], edge[1]
		ci, okC := indexOf(seedTables, child)
		pi, okP := indexOf(seedTables, parent)
		if !okC {
			t.Errorf("child %q not in seedTables", child)
			continue
		}
		if !okP {
			t.Errorf("parent %q not in seedTables", parent)
			continue
		}
		if ci >= pi {
			t.Errorf("child %q (pos %d) must be truncated before parent %q (pos %d)", child, ci, parent, pi)
		}
	}
}

func TestSeedTablesNoDuplicates(t *testing.T) {
	seen := make(map[string]bool, len(seedTables))
	for _, table := range seedTables {
		if seen[table] {
			t.Errorf("duplicate table %q in seedTables", table)
		}
		seen[table] = true
	}
}

func contains(tables []string, want string) bool {
	_, ok := indexOf(tables, want)
	return ok
}

func indexOf(tables []string, want string) (int, bool) {
	for i, table := range tables {
		if table == want {
			return i, true
		}
	}
	return -1, false
}