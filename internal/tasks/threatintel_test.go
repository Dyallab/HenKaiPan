package tasks

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"aspm/internal/datascope"
	"aspm/internal/models"
	"aspm/internal/repository"
	"aspm/internal/threats"

	"github.com/hibiken/asynq"
)

// ── fakes (no redis, no network) ────────────────────────────────────────────

type fakeProjectLister struct {
	projects []models.Project
	err      error
}

func (f *fakeProjectLister) ListAllProjects(_ context.Context, _ datascope.Scope, _ string) ([]models.Project, error) {
	return f.projects, f.err
}

type fakeThreatStore struct {
	deps map[string][]threats.Dependency
	advs []threats.Advisory
	hits map[string][]repository.ThreatHit
}

func newFakeThreatStore() *fakeThreatStore {
	return &fakeThreatStore{
		deps: map[string][]threats.Dependency{},
		hits: map[string][]repository.ThreatHit{},
	}
}

func (f *fakeThreatStore) UpsertDependencies(_ context.Context, projectID string, deps []threats.Dependency) error {
	f.deps[projectID] = deps
	return nil
}

func (f *fakeThreatStore) UpsertAdvisories(_ context.Context, advs []threats.Advisory, _ func(cveID string, aliases []string) bool) error {
	f.advs = advs
	return nil
}

func (f *fakeThreatStore) InsertHits(_ context.Context, projectID string, hits []repository.ThreatHit) error {
	f.hits[projectID] = hits
	return nil
}

type fakeEnqueuer struct {
	ch chan *asynq.Task
}

func (f *fakeEnqueuer) EnqueueContext(_ context.Context, task *asynq.Task, _ ...asynq.Option) (*asynq.TaskInfo, error) {
	f.ch <- task
	return nil, nil
}

// ── payload round-trip ──────────────────────────────────────────────────────

func TestThreatIntelPayloadRoundTrip(t *testing.T) {
	raw, err := MarshalThreatSyncPayload(ThreatSyncPayload{ProjectID: "proj-1"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got, err := UnmarshalThreatSyncPayload(raw)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.ProjectID != "proj-1" {
		t.Fatalf("project_id = %q, want proj-1", got.ProjectID)
	}
}

// ── Hit → ThreatHit mapping ─────────────────────────────────────────────────

func TestThreatIntelHitMapping(t *testing.T) {
	hit := threats.Hit{
		AdvisoryID:      "GHSA-test-1",
		CVEID:           "CVE-2021-44228",
		PkgName:         "lodash",
		PkgVersion:      "4.17.21",
		InventoryStatus: threats.StatusDeclared,
		MatchStatus:     threats.MatchUnconfirmed,
		Evidence:        map[string]any{"declared": map[string]any{"name": "lodash"}},
	}
	got := threatHitFromMatch(hit)
	if got.AdvisoryID != "GHSA-test-1" {
		t.Fatalf("advisory_id = %q", got.AdvisoryID)
	}
	if got.PkgName != "lodash" || got.PkgVersion != "4.17.21" {
		t.Fatalf("pkg = %q %q", got.PkgName, got.PkgVersion)
	}
	if got.InventoryStatus != threats.StatusDeclared {
		t.Fatalf("inventory_status = %q", got.InventoryStatus)
	}
	if got.MatchStatus != threats.MatchUnconfirmed {
		t.Fatalf("match_status = %q", got.MatchStatus)
	}
	if got.RuntimeStatus != "L0" {
		t.Fatalf("runtime_status = %q, want L0 default", got.RuntimeStatus)
	}
	var ev map[string]any
	if err := json.Unmarshal(got.Evidence, &ev); err != nil {
		t.Fatalf("evidence is not JSON: %v", err)
	}
	if _, ok := ev["declared"]; !ok {
		t.Fatalf("evidence missing declared key: %s", got.Evidence)
	}
}

// ── handler sync flow with injected fakes ───────────────────────────────────

func threatSyncTestDeps(store *fakeThreatStore, queried *[]threats.Dependency) ThreatSyncDeps {
	return ThreatSyncDeps{
		Projects: &fakeProjectLister{projects: []models.Project{{ID: "proj-1", Name: "p1"}}},
		Threats:  store,
		FetchManifest: func(_ context.Context, _ models.Project) (string, []byte, error) {
			return "package.json", []byte(`{"dependencies":{"lodash":"4.17.21"}}`), nil
		},
		QueryOSV: func(_ context.Context, deps []threats.Dependency) ([]threats.Advisory, error) {
			*queried = deps
			return []threats.Advisory{{
				AdvisoryID: "GHSA-test-1",
				Source:     "osv",
				CVEID:      "CVE-2021-44228",
				AffectedPackages: []threats.AffectedPackage{
					{Ecosystem: "npm", Name: "lodash"},
				},
			}}, nil
		},
		FetchKEV: func(_ context.Context) (map[string]threats.KEVEntry, error) {
			return map[string]threats.KEVEntry{}, nil
		},
	}
}

func TestThreatIntelSync(t *testing.T) {
	store := newFakeThreatStore()
	var queried []threats.Dependency
	handler := HandleThreatSync(threatSyncTestDeps(store, &queried))

	payload, err := MarshalThreatSyncPayload(ThreatSyncPayload{})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := handler(context.Background(), asynq.NewTask(TypeThreatSync, payload)); err != nil {
		t.Fatalf("handler: %v", err)
	}

	if got := len(store.deps["proj-1"]); got != 1 {
		t.Fatalf("deps upserted = %d, want 1", got)
	}
	if len(queried) != 1 || queried[0].Name != "lodash" {
		t.Fatalf("osv queried deps = %+v, want [lodash]", queried)
	}
	if got := len(store.advs); got != 1 {
		t.Fatalf("advisories upserted = %d, want 1", got)
	}
	hits := store.hits["proj-1"]
	if len(hits) != 1 {
		t.Fatalf("hits inserted = %d, want 1", len(hits))
	}
	h := hits[0]
	if h.AdvisoryID != "GHSA-test-1" || h.PkgName != "lodash" {
		t.Fatalf("unexpected hit: %+v", h)
	}
	if h.RuntimeStatus != "L0" {
		t.Fatalf("runtime_status = %q, want L0", h.RuntimeStatus)
	}
	var ev map[string]any
	if err := json.Unmarshal(h.Evidence, &ev); err != nil {
		t.Fatalf("evidence is not JSON: %v", err)
	}
}

// ── scheduler: immediate run + ticker ───────────────────────────────────────

func TestThreatIntelMonitorImmediateRun(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fake := &fakeEnqueuer{ch: make(chan *asynq.Task, 10)}
	// Hour interval proves the immediate run: exactly one task must arrive promptly.
	StartThreatIntelMonitor(ctx, repository.Stores{}, fake, time.Hour)

	select {
	case task := <-fake.ch:
		if task.Type() != TypeThreatSync {
			t.Fatalf("task type = %q, want %q", task.Type(), TypeThreatSync)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no threat:sync enqueued on monitor start")
	}
}

func TestThreatIntelMonitorTicker(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fake := &fakeEnqueuer{ch: make(chan *asynq.Task, 10)}
	StartThreatIntelMonitor(ctx, repository.Stores{}, fake, 10*time.Millisecond)

	count := 0
	timeout := time.After(2 * time.Second)
	for count < 2 {
		select {
		case <-fake.ch:
			count++
		case <-timeout:
			t.Fatalf("only %d threat:sync tasks in 2s, want >= 2", count)
		}
	}
}
