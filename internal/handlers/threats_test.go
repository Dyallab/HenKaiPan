package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"aspm/internal/assert"
	"aspm/internal/auth"
	"aspm/internal/repository"
	"aspm/internal/threats"
)

var errExposuresOwnership = errors.New("ownership check boom")

// ── Mock ThreatRepository ───────────────────────────────────────────────────

type mockThreatRepo struct {
	rows       []repository.ExposureRow
	total      int
	err        error
	lastFilter repository.ExposureFilter
}

func (m *mockThreatRepo) UpsertDependencies(_ context.Context, _ string, _ []threats.Dependency) error {
	return nil
}

func (m *mockThreatRepo) UpsertAdvisories(_ context.Context, _ []threats.Advisory, _ func(cveID string, aliases []string) bool) error {
	return nil
}

func (m *mockThreatRepo) InsertHits(_ context.Context, _ string, _ []repository.ThreatHit) error {
	return nil
}

func (m *mockThreatRepo) ListExposures(_ context.Context, f repository.ExposureFilter) ([]repository.ExposureRow, int, error) {
	m.lastFilter = f
	if m.err != nil {
		return nil, 0, m.err
	}
	return m.rows, m.total, nil
}

// ── Mock AppRepository (ownership only; embeds interface for the rest) ───────

type mockAppsRepo struct {
	repository.AppRepository
	owned map[string]bool
	err   error
}

func (m *mockAppsRepo) CheckProjectOwnership(_ context.Context, _, projectID string) (bool, error) {
	if m.err != nil {
		return false, m.err
	}
	return m.owned[projectID], nil
}

// ── Helpers ─────────────────────────────────────────────────────────────────

func newExposuresTestHandler(threatsRepo *mockThreatRepo) *Handler {
	// Default: owns proj-1 so pre-existing non-admin tests keep passing.
	return newExposuresTestHandlerWithApps(threatsRepo, &mockAppsRepo{owned: map[string]bool{"proj-1": true}})
}

func newExposuresTestHandlerWithApps(threatsRepo *mockThreatRepo, apps repository.AppRepository) *Handler {
	return &Handler{
		store: repository.Stores{
			Threats: threatsRepo,
			Apps:    apps,
		},
	}
}

func exposuresReq(t *testing.T, target, userID, username, role string) *http.Request {
	t.Helper()
	token, err := auth.IssueToken(username, role, userID, 0)
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, target, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	return req
}

func serveExposures(h *Handler, req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	auth.JWTMiddleware(http.HandlerFunc(h.ListThreatExposures)).ServeHTTP(rec, req)
	return rec
}

func seedExposureRow() repository.ExposureRow {
	return repository.ExposureRow{
		HitID:           "hit-1",
		ProjectID:       "proj-1",
		AdvisoryID:      "GHSA-xxxx-yyyy",
		Source:          "osv",
		CVEID:           "CVE-2024-1234",
		Ecosystem:       "npm",
		PkgName:         "lodash",
		PkgVersion:      "4.17.20",
		Severity:        "HIGH",
		KEV:             true,
		InventoryStatus: "declared",
		RuntimeStatus:   "L2",
		MatchStatus:     "active_threat",
		CreatedAt:       time.Now(),
	}
}

// ── 200 envelope shape ──────────────────────────────────────────────────────

func TestExposures_ReturnsEnvelopeWithDualStatusFields(t *testing.T) {
	repo := &mockThreatRepo{rows: []repository.ExposureRow{seedExposureRow()}, total: 1}
	h := newExposuresTestHandler(repo)

	rec := serveExposures(h, exposuresReq(t, "/api/threats/exposures?project_id=proj-1", "usr-admin", "alice", "admin"))

	assert.Equal(t, rec.Code, http.StatusOK)

	var resp map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	rawExposures, ok := resp["exposures"]
	if !ok {
		t.Fatalf("envelope missing 'exposures' key: %s", rec.Body.String())
	}
	rawTotal, ok := resp["total"]
	if !ok {
		t.Fatalf("envelope missing 'total' key: %s", rec.Body.String())
	}
	assert.Equal(t, string(rawTotal), "1")

	var exposures []map[string]any
	if err := json.Unmarshal(rawExposures, &exposures); err != nil {
		t.Fatalf("decode exposures: %v", err)
	}
	assert.Equal(t, len(exposures), 1)
	row := exposures[0]
	// Dual inventory/runtime status + KEV + match status identify an exposure.
	for _, key := range []string{
		"hit_id", "project_id", "advisory_id", "cve_id", "pkg_name", "pkg_version",
		"severity", "kev", "inventory_status", "runtime_status", "match_status",
	} {
		if _, ok := row[key]; !ok {
			t.Errorf("exposure row missing %q: %v", key, row)
		}
	}
	assert.Equal(t, row["inventory_status"], "declared")
	assert.Equal(t, row["runtime_status"], "L2")
	assert.Equal(t, row["kev"], true)
	assert.Equal(t, row["match_status"], "active_threat")
}

// ── 401 without token ───────────────────────────────────────────────────────

func TestExposures_UnauthorizedWithoutToken(t *testing.T) {
	repo := &mockThreatRepo{rows: []repository.ExposureRow{seedExposureRow()}, total: 1}
	h := newExposuresTestHandler(repo)

	// Direct call without JWT middleware: no claims in context.
	req := httptest.NewRequest(http.MethodGet, "/api/threats/exposures", nil)
	rec := httptest.NewRecorder()
	h.ListThreatExposures(rec, req)

	assert.Equal(t, rec.Code, http.StatusUnauthorized)
}

// ── Pagination defaults ─────────────────────────────────────────────────────

func TestExposures_PaginationDefaults(t *testing.T) {
	repo := &mockThreatRepo{rows: nil, total: 0}
	h := newExposuresTestHandler(repo)

	rec := serveExposures(h, exposuresReq(t, "/api/threats/exposures", "usr-admin", "alice", "admin"))

	assert.Equal(t, rec.Code, http.StatusOK)
	assert.Equal(t, repo.lastFilter.Page, 1)
	assert.Equal(t, repo.lastFilter.Limit, 100)
}

// ── KEV + match_status filters ──────────────────────────────────────────────

func TestExposures_KEVAndMatchStatusFilters(t *testing.T) {
	repo := &mockThreatRepo{rows: nil, total: 0}
	h := newExposuresTestHandler(repo)

	rec := serveExposures(h, exposuresReq(t,
		"/api/threats/exposures?project_id=proj-1&kev=true&match_status=active_threat&inventory_status=declared&q=lodash&sort=severity",
		"usr-admin", "alice", "admin"))

	assert.Equal(t, rec.Code, http.StatusOK)
	assert.Equal(t, repo.lastFilter.ProjectID, "proj-1")
	assert.True(t, repo.lastFilter.KEVOnly)
	assert.Equal(t, repo.lastFilter.MatchStatus, "active_threat")
	assert.Equal(t, repo.lastFilter.InventoryStatus, "declared")
	assert.Equal(t, repo.lastFilter.Q, "lodash")
	assert.Equal(t, repo.lastFilter.Sort, "severity")
}

// ── Non-admin datascope scoping ─────────────────────────────────────────────
// ExposureFilter carries no user field (repo is project-scoped), so the
// handler enforces scoping at the edge: non-admin callers must name a
// project_id; admins may list across projects.

func TestExposures_NonAdminRequiresProjectID(t *testing.T) {
	repo := &mockThreatRepo{rows: nil, total: 0}
	h := newExposuresTestHandler(repo)

	rec := serveExposures(h, exposuresReq(t, "/api/threats/exposures", "usr-bob", "bob", "viewer"))

	assert.Equal(t, rec.Code, http.StatusForbidden)
}

func TestExposures_NonAdminScopedToProject(t *testing.T) {
	repo := &mockThreatRepo{rows: []repository.ExposureRow{seedExposureRow()}, total: 1}
	h := newExposuresTestHandler(repo)

	rec := serveExposures(h, exposuresReq(t, "/api/threats/exposures?project_id=proj-1", "usr-bob", "bob", "viewer"))

	assert.Equal(t, rec.Code, http.StatusOK)
	assert.Equal(t, repo.lastFilter.ProjectID, "proj-1")

	var resp struct {
		Total int `json:"total"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	assert.Equal(t, resp.Total, 1)
}

// ── Non-admin project ownership (IDOR, PR #73) ──────────────────────────────
// Non-admin callers must only read projects they own; admins bypass the check.

func TestExposures_NonAdminUnownedProjectForbidden(t *testing.T) {
	repo := &mockThreatRepo{rows: []repository.ExposureRow{seedExposureRow()}, total: 1}
	apps := &mockAppsRepo{owned: map[string]bool{"proj-other": true}}
	h := newExposuresTestHandlerWithApps(repo, apps)

	rec := serveExposures(h, exposuresReq(t, "/api/threats/exposures?project_id=proj-1", "usr-bob", "bob", "viewer"))

	assert.Equal(t, rec.Code, http.StatusForbidden)
}

func TestExposures_NonAdminOwnedProjectAllowed(t *testing.T) {
	repo := &mockThreatRepo{rows: []repository.ExposureRow{seedExposureRow()}, total: 1}
	apps := &mockAppsRepo{owned: map[string]bool{"proj-1": true}}
	h := newExposuresTestHandlerWithApps(repo, apps)

	rec := serveExposures(h, exposuresReq(t, "/api/threats/exposures?project_id=proj-1", "usr-bob", "bob", "viewer"))

	assert.Equal(t, rec.Code, http.StatusOK)
	assert.Equal(t, repo.lastFilter.ProjectID, "proj-1")
}

func TestExposures_AdminBypassesOwnership(t *testing.T) {
	repo := &mockThreatRepo{rows: []repository.ExposureRow{seedExposureRow()}, total: 1}
	apps := &mockAppsRepo{owned: map[string]bool{}}
	h := newExposuresTestHandlerWithApps(repo, apps)

	rec := serveExposures(h, exposuresReq(t, "/api/threats/exposures?project_id=proj-1", "usr-admin", "alice", "admin"))

	assert.Equal(t, rec.Code, http.StatusOK)
}

func TestExposures_OwnershipCheckErrorIs500(t *testing.T) {
	repo := &mockThreatRepo{rows: []repository.ExposureRow{seedExposureRow()}, total: 1}
	apps := &mockAppsRepo{owned: map[string]bool{"proj-1": true}, err: errExposuresOwnership}
	h := newExposuresTestHandlerWithApps(repo, apps)

	rec := serveExposures(h, exposuresReq(t, "/api/threats/exposures?project_id=proj-1", "usr-bob", "bob", "viewer"))

	assert.Equal(t, rec.Code, http.StatusInternalServerError)
}
