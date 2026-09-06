//go:build integration

package repository

import (
	"context"
	"testing"

	"aspm/internal/assert"
	"aspm/internal/datascope"
	"aspm/internal/testdb"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// newTestStores connects to the shared test Postgres, wipes the seed tables,
// and returns the repository Stores wired against the pool.
func newTestStores(t *testing.T) (Stores, *pgxpool.Pool) {
	t.Helper()
	pool := testdb.Connect(t)
	testdb.Reset(t, pool)
	return NewPostgresStores(pool, ""), pool
}

func boolPtr(b bool) *bool { return &b }

// ── Users ────────────────────────────────────────────────────────────────────

func TestUsersCRUD(t *testing.T) {
	stores, _ := newTestStores(t)
	ctx := context.Background()

	created, err := stores.Users.Create(ctx, UserCreate{
		Username:     "alice",
		Email:        "alice@example.com",
		PasswordHash: "hash",
		Role:         "admin",
	})
	assert.NoError(t, err)
	assert.NotNil(t, created)
	assert.True(t, created.IsActive)
	assert.Equal(t, created.Username, "alice")
	assert.Equal(t, created.Email, "alice@example.com")
	assert.Equal(t, created.Role, "admin")

	// Lookup by email, username, and id all resolve to the same row.
	byEmail, err := stores.Users.GetUserByEmail(ctx, "alice@example.com")
	assert.NoError(t, err)
	assert.Equal(t, byEmail.ID, created.ID)

	byUsername, err := stores.Users.GetByUsername(ctx, "alice")
	assert.NoError(t, err)
	assert.Equal(t, byUsername.ID, created.ID)

	byID, err := stores.Users.GetByID(ctx, created.ID)
	assert.NoError(t, err)
	assert.Equal(t, byID.Username, "alice")

	// Unique constraints: duplicate email and duplicate username are rejected.
	_, err = stores.Users.Create(ctx, UserCreate{Username: "alice2", Email: "alice@example.com", PasswordHash: "h", Role: "viewer"})
	assert.NotNil(t, err)
	_, err = stores.Users.Create(ctx, UserCreate{Username: "alice", Email: "alice2@example.com", PasswordHash: "h", Role: "viewer"})
	assert.NotNil(t, err)

	// Deactivate: is_active flips to false.
	updated, err := stores.Users.Update(ctx, created.ID, UserUpdate{IsActive: boolPtr(false)})
	assert.NoError(t, err)
	assert.False(t, updated.IsActive)

	active, err := stores.Users.IsActive(ctx, created.ID)
	assert.NoError(t, err)
	assert.False(t, active)

	// Token version starts at 0 and bumps by 1.
	v0, err := stores.Users.GetTokenVersion(ctx, created.ID)
	assert.NoError(t, err)
	assert.Equal(t, v0, 0)
	assert.NoError(t, stores.Users.BumpTokenVersion(ctx, created.ID))
	v1, err := stores.Users.GetTokenVersion(ctx, created.ID)
	assert.NoError(t, err)
	assert.Equal(t, v1, 1)

	// Delete removes the row; subsequent lookups return pgx.ErrNoRows.
	assert.NoError(t, stores.Users.Delete(ctx, created.ID))
	_, err = stores.Users.GetByID(ctx, created.ID)
	assert.ErrorIs(t, err, pgx.ErrNoRows)
}

// ── Teams ────────────────────────────────────────────────────────────────────

func TestTeamsCRUD(t *testing.T) {
	stores, _ := newTestStores(t)
	ctx := context.Background()

	team, err := stores.Teams.Create(ctx, "platform")
	assert.NoError(t, err)
	assert.NotNil(t, team)
	assert.Equal(t, team.Name, "platform")

	// Team names are unique.
	_, err = stores.Teams.Create(ctx, "platform")
	assert.NotNil(t, err)

	teams, err := stores.Teams.List(ctx)
	assert.NoError(t, err)
	assert.Equal(t, len(teams), 1)
	assert.Equal(t, teams[0].ID, team.ID)
	assert.Equal(t, len(teams[0].Members), 0)

	// AddMember inserts a (team_id, user_id) row; duplicate add is idempotent.
	user, err := stores.Users.Create(ctx, UserCreate{Username: "bob", Email: "bob@example.com", PasswordHash: "h", Role: "viewer"})
	assert.NoError(t, err)
	assert.NoError(t, stores.Teams.AddMember(ctx, team.ID, user.ID))
	assert.NoError(t, stores.Teams.AddMember(ctx, team.ID, user.ID))

	teams, err = stores.Teams.List(ctx)
	assert.NoError(t, err)
	assert.Equal(t, len(teams[0].Members), 1)
	assert.Equal(t, teams[0].Members[0].ID, user.ID)

	// RemoveMember deletes the composite-PK row.
	assert.NoError(t, stores.Teams.RemoveMember(ctx, team.ID, user.ID))
	teams, err = stores.Teams.List(ctx)
	assert.NoError(t, err)
	assert.Equal(t, len(teams[0].Members), 0)

	// Delete removes the team.
	assert.NoError(t, stores.Teams.Delete(ctx, team.ID))
	teams, err = stores.Teams.List(ctx)
	assert.NoError(t, err)
	assert.Equal(t, len(teams), 0)
}

// ── Apps ─────────────────────────────────────────────────────────────────────

func TestAppsCRUD(t *testing.T) {
	stores, _ := newTestStores(t)
	ctx := context.Background()

	team, err := stores.Teams.Create(ctx, "sec")
	assert.NoError(t, err)

	app, err := stores.Apps.Create(ctx, "core", "main app", &team.ID)
	assert.NoError(t, err)
	assert.NotNil(t, app)
	assert.Equal(t, app.Name, "core")
	assert.Equal(t, app.Description, "main app")
	assert.NotNil(t, app.TeamID)
	assert.Equal(t, *app.TeamID, team.ID)

	got, err := stores.Apps.Get(ctx, app.ID)
	assert.NoError(t, err)
	assert.Equal(t, got.ID, app.ID)
	assert.Equal(t, got.Name, "core")

	// Admin scope lists every app.
	apps, err := stores.Apps.List(ctx, datascope.Admin())
	assert.NoError(t, err)
	assert.Equal(t, len(apps), 1)
	assert.Equal(t, apps[0].ID, app.ID)

	// Apps may exist without a team.
	noTeam, err := stores.Apps.Create(ctx, "no-team", "", nil)
	assert.NoError(t, err)
	assert.Nil(t, noTeam.TeamID)

	// App names are unique.
	_, err = stores.Apps.Create(ctx, "core", "", nil)
	assert.NotNil(t, err)
}

// ── Projects ─────────────────────────────────────────────────────────────────

func TestProjectsStandaloneUnique(t *testing.T) {
	stores, _ := newTestStores(t)
	ctx := context.Background()

	p, err := stores.Apps.CreateStandaloneProject(ctx, ProjectCreate{
		Name:          "standalone-repo",
		Description:   "desc",
		RepoURL:       "https://github.com/acme/standalone-repo",
		Provider:      "github",
		DefaultBranch: "main",
		Tags:          []string{"go"},
	})
	assert.NoError(t, err)
	assert.NotNil(t, p)
	assert.Nil(t, p.AppID)
	assert.Equal(t, p.Name, "standalone-repo")
	assert.Equal(t, p.Provider, "github")

	// GetProjectByName resolves standalone projects (app_id IS NULL).
	got, err := stores.Apps.GetProjectByName(ctx, "standalone-repo")
	assert.NoError(t, err)
	assert.Equal(t, got.ID, p.ID)

	// Standalone names are globally unique (partial unique index).
	_, err = stores.Apps.CreateStandaloneProject(ctx, ProjectCreate{Name: "standalone-repo"})
	assert.NotNil(t, err)

	// An app-scoped project may reuse the standalone name without colliding.
	app, err := stores.Apps.Create(ctx, "app1", "", nil)
	assert.NoError(t, err)
	scoped, err := stores.Apps.CreateProject(ctx, app.ID, ProjectCreate{Name: "standalone-repo"})
	assert.NoError(t, err)
	assert.NotNil(t, scoped.AppID)
	assert.Equal(t, *scoped.AppID, app.ID)

	// GetProjectByName still returns the standalone row, not the app-scoped one.
	got, err = stores.Apps.GetProjectByName(ctx, "standalone-repo")
	assert.NoError(t, err)
	assert.Equal(t, got.ID, p.ID)
}

func TestProjectsSameNameAcrossApps(t *testing.T) {
	stores, _ := newTestStores(t)
	ctx := context.Background()

	app1, err := stores.Apps.Create(ctx, "app1", "", nil)
	assert.NoError(t, err)
	app2, err := stores.Apps.Create(ctx, "app2", "", nil)
	assert.NoError(t, err)

	// Same project name in two different apps is allowed (partial unique on (app_id, name)).
	p1, err := stores.Apps.CreateProject(ctx, app1.ID, ProjectCreate{Name: "shared-name", RepoURL: "https://github.com/acme/a"})
	assert.NoError(t, err)
	p2, err := stores.Apps.CreateProject(ctx, app2.ID, ProjectCreate{Name: "shared-name", RepoURL: "https://github.com/acme/b"})
	assert.NoError(t, err)
	assert.NotEqual(t, p1.ID, p2.ID)

	// Duplicate within the same app is rejected.
	_, err = stores.Apps.CreateProject(ctx, app1.ID, ProjectCreate{Name: "shared-name"})
	assert.NotNil(t, err)
}

// ── Ownership ────────────────────────────────────────────────────────────────

func TestOwnershipChecks(t *testing.T) {
	stores, _ := newTestStores(t)
	ctx := context.Background()

	team, err := stores.Teams.Create(ctx, "sec")
	assert.NoError(t, err)

	admin, err := stores.Users.Create(ctx, UserCreate{Username: "admin1", Email: "admin1@example.com", PasswordHash: "h", Role: "admin"})
	assert.NoError(t, err)
	viewer, err := stores.Users.Create(ctx, UserCreate{Username: "viewer1", Email: "viewer1@example.com", PasswordHash: "h", Role: "viewer"})
	assert.NoError(t, err)
	outsider, err := stores.Users.Create(ctx, UserCreate{Username: "outsider", Email: "outsider@example.com", PasswordHash: "h", Role: "viewer"})
	assert.NoError(t, err)

	// admin and viewer are team members; outsider is not.
	assert.NoError(t, stores.Teams.AddMember(ctx, team.ID, admin.ID))
	assert.NoError(t, stores.Teams.AddMember(ctx, team.ID, viewer.ID))

	app, err := stores.Apps.Create(ctx, "core", "", &team.ID)
	assert.NoError(t, err)
	project, err := stores.Apps.CreateProject(ctx, app.ID, ProjectCreate{Name: "svc"})
	assert.NoError(t, err)

	// App ownership: member (admin or viewer) → true, non-member → false.
	ok, err := stores.Apps.CheckAppOwnership(ctx, admin.ID, app.ID)
	assert.NoError(t, err)
	assert.True(t, ok)

	ok, err = stores.Apps.CheckAppOwnership(ctx, viewer.ID, app.ID)
	assert.NoError(t, err)
	assert.True(t, ok)

	ok, err = stores.Apps.CheckAppOwnership(ctx, outsider.ID, app.ID)
	assert.NoError(t, err)
	assert.False(t, ok)

	// Project ownership: same membership path through team → app → project.
	ok, err = stores.Apps.CheckProjectOwnership(ctx, admin.ID, project.ID)
	assert.NoError(t, err)
	assert.True(t, ok)

	ok, err = stores.Apps.CheckProjectOwnership(ctx, viewer.ID, project.ID)
	assert.NoError(t, err)
	assert.True(t, ok)

	ok, err = stores.Apps.CheckProjectOwnership(ctx, outsider.ID, project.ID)
	assert.NoError(t, err)
	assert.False(t, ok)

	// Standalone projects have no app, so no membership row can grant ownership.
	standalone, err := stores.Apps.CreateStandaloneProject(ctx, ProjectCreate{Name: "standalone"})
	assert.NoError(t, err)
	ok, err = stores.Apps.CheckProjectOwnership(ctx, admin.ID, standalone.ID)
	assert.NoError(t, err)
	assert.False(t, ok)
}