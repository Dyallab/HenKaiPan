// Package datascope controls data visibility in the repository layer.
//
// It provides a Scope struct used by all list queries to enforce
// team-based data isolation. Admin users see everything; non-admin
// users see only data belonging to their team(s).
//
// IMPORTANT: Never use Scope{} directly — always use Admin() or ForUser().
// The zero value is intentionally undocumented to make accidental
// fail-open abuse visible in code review.
package datascope

// Scope controls which data a list query returns.
//
// Zero value is Admin (no filtering), but CONSTRUCTORS MUST BE USED:
//
//	scope := datascope.Admin()        // admin sees everything
//	scope := datascope.ForUser(id)    // scoped to user's teams
//
// Future extension points (add fields, never break existing callers):
//   TeamIDs    []string // auditor with multi-team access (use EXISTS ANY)
//   Permission string   // RBAC: "findings:read", "scans:write"
type Scope struct {
	// UserID is nil for admin (no filter) or a user UUID for scoped access.
	UserID *string
}

// Admin returns a Scope with no filtering — admin sees all data.
func Admin() Scope {
	return Scope{}
}

// ForUser returns a Scope filtering data to the given user's teams.
func ForUser(userID string) Scope {
	return Scope{UserID: &userID}
}
