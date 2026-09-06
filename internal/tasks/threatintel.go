package tasks

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"aspm/internal/datascope"
	"aspm/internal/models"
	"aspm/internal/repository"
	"aspm/internal/threats"

	"github.com/hibiken/asynq"
)

// Threat-intel sync scheduler + job (issue #64).
//
// Every interval the monitor enqueues one threat:sync task; the handler
// lists projects, parses each project's manifest inventory, resolves it
// against OSV, overlays the CISA KEV catalog, correlates with
// threats.Match (findings empty for MVP), and persists via store.Threats.
// No notification pipeline here — that is a later issue's job.

const TypeThreatSync = "threat:sync"

// ThreatSyncPayload selects the sync scope. Empty ProjectID syncs all projects.
type ThreatSyncPayload struct {
	ProjectID string `json:"project_id,omitempty"`
}

func MarshalThreatSyncPayload(p ThreatSyncPayload) ([]byte, error) {
	return json.Marshal(p)
}

func UnmarshalThreatSyncPayload(data []byte) (ThreatSyncPayload, error) {
	var p ThreatSyncPayload
	return p, json.Unmarshal(data, &p)
}

// ProjectLister lists projects for the sync (admin scope).
type ProjectLister interface {
	ListAllProjects(ctx context.Context, scope datascope.Scope, appFilter string) ([]models.Project, error)
}

// ThreatStore persists threat-intel data (subset of repository.ThreatRepository).
type ThreatStore interface {
	UpsertDependencies(ctx context.Context, projectID string, deps []threats.Dependency) error
	UpsertAdvisories(ctx context.Context, advs []threats.Advisory, isKEV func(cveID string, aliases []string) bool) error
	InsertHits(ctx context.Context, projectID string, hits []repository.ThreatHit) error
}

// ThreatEnqueuer abstracts asynq.Client so the scheduler is unit-testable.
type ThreatEnqueuer interface {
	EnqueueContext(ctx context.Context, task *asynq.Task, opts ...asynq.Option) (*asynq.TaskInfo, error)
}

// ThreatSyncDeps wires the sync flow. FetchManifest / QueryOSV / FetchKEV are
// func fields so tests inject fakes and never hit the network.
// Queue + Notify are optional: when both are set, syncProject fans out
// NotifyForHits after InsertHits (KEV notifies + silent rescans, no new
// pipeline). Nil Queue/Notify disables fan-out (unit-test default).
type ThreatSyncDeps struct {
	Projects      ProjectLister
	Threats       ThreatStore
	FetchManifest func(ctx context.Context, project models.Project) (sourceFile string, data []byte, err error)
	QueryOSV      func(ctx context.Context, deps []threats.Dependency) ([]threats.Advisory, error)
	FetchKEV      func(ctx context.Context) (map[string]threats.KEVEntry, error)
	Queue         ThreatEnqueuer
	Notify        *ThreatNotifyDeps
}

// ErrNoManifestSource is returned by the default manifest fetcher: the MVP
// has no inventory source wired yet, so projects are skipped (not failed).
var ErrNoManifestSource = errors.New("threatintel: no manifest source configured")

// DefaultThreatSyncDeps builds production deps: real OSV + KEV clients,
// projects and threat store from the repository bundle.
func DefaultThreatSyncDeps(store repository.Stores) ThreatSyncDeps {
	osvClient := threats.NewClient("", "henkaipan-worker")
	return ThreatSyncDeps{
		Projects: store.Apps,
		Threats:  store.Threats,
		FetchManifest: func(_ context.Context, _ models.Project) (string, []byte, error) {
			return "", nil, ErrNoManifestSource
		},
		QueryOSV: osvClient.Query,
		FetchKEV: func(ctx context.Context) (map[string]threats.KEVEntry, error) {
			return threats.FetchKEV(ctx, nil, "")
		},
	}
}

// StartThreatIntelMonitor enqueues a threat:sync task immediately on start
// and then on every interval (StartSLABreachMonitor pattern). Non-positive
// intervals default to 6h.
func StartThreatIntelMonitor(ctx context.Context, _ repository.Stores, queue ThreatEnqueuer, interval time.Duration) {
	if interval <= 0 {
		interval = 6 * time.Hour
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		enqueueThreatSync(ctx, queue)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				enqueueThreatSync(ctx, queue)
			}
		}
	}()
}

func enqueueThreatSync(ctx context.Context, queue ThreatEnqueuer) {
	payload, err := MarshalThreatSyncPayload(ThreatSyncPayload{})
	if err != nil {
		slog.Warn("marshal threat:sync payload failed", "err", err)
		return
	}
	if _, err := queue.EnqueueContext(ctx,
		asynq.NewTask(TypeThreatSync, payload),
		asynq.MaxRetry(3),
		asynq.Timeout(30*time.Minute),
	); err != nil {
		slog.Warn("enqueue threat:sync failed", "err", err)
		return
	}
	slog.Info("threat sync enqueued")
}

// HandleThreatSync runs the threat-intel sync for the payload scope.
func HandleThreatSync(deps ThreatSyncDeps) asynq.HandlerFunc {
	return func(ctx context.Context, t *asynq.Task) error {
		p, err := UnmarshalThreatSyncPayload(t.Payload())
		if err != nil {
			return fmt.Errorf("unmarshal threat sync payload: %w", err)
		}
		return SyncThreatIntel(ctx, deps, p.ProjectID)
	}
}

// SyncThreatIntel syncs one project (projectID != "") or all projects.
// Per-project failures are logged and skipped; listing failure is fatal.
func SyncThreatIntel(ctx context.Context, deps ThreatSyncDeps, projectID string) error {
	var projects []models.Project
	if projectID != "" {
		projects = []models.Project{{ID: projectID}}
	} else {
		list, err := deps.Projects.ListAllProjects(ctx, datascope.Admin(), "")
		if err != nil {
			return fmt.Errorf("list projects for threat sync: %w", err)
		}
		projects = list
	}
	slog.Info("threat sync started", "projects", len(projects))

	kev, err := deps.FetchKEV(ctx)
	if err != nil {
		slog.Warn("kev fetch failed, continuing without kev overlay", "err", err)
		kev = map[string]threats.KEVEntry{}
	}
	slog.Info("threat sync kev loaded", "entries", len(kev))

	synced, skipped := 0, 0
	for _, project := range projects {
		if err := syncProject(ctx, deps, project, kev); err != nil {
			if errors.Is(err, ErrNoManifestSource) {
				slog.Info("threat sync skipped project", "project_id", project.ID, "reason", "no manifest source")
			} else {
				slog.Warn("threat sync project failed", "project_id", project.ID, "err", err)
			}
			skipped++
			continue
		}
		synced++
	}
	slog.Info("threat sync completed", "synced", synced, "skipped", skipped)
	return nil
}

func syncProject(ctx context.Context, deps ThreatSyncDeps, project models.Project, kev map[string]threats.KEVEntry) error {
	log := slog.With("project_id", project.ID)

	sourceFile, data, err := deps.FetchManifest(ctx, project)
	if err != nil {
		return err
	}
	inventory, err := threats.ParseManifest(sourceFile, data)
	if err != nil {
		return fmt.Errorf("parse manifest %s: %w", sourceFile, err)
	}
	log.Info("threat sync inventory parsed", "manifest", sourceFile, "deps", len(inventory))

	if err := deps.Threats.UpsertDependencies(ctx, project.ID, inventory); err != nil {
		return fmt.Errorf("upsert dependencies: %w", err)
	}

	advisories, err := deps.QueryOSV(ctx, inventory)
	if err != nil {
		return fmt.Errorf("osv query: %w", err)
	}
	log.Info("threat sync osv resolved", "advisories", len(advisories))

	if err := deps.Threats.UpsertAdvisories(ctx, advisories, func(cveID string, aliases []string) bool {
		return threats.IsKEV(cveID, aliases, kev)
	}); err != nil {
		return fmt.Errorf("upsert advisories: %w", err)
	}

	// MVP: findings empty — scanner corroboration lands with runtime inventory.
	hits := threats.Match(inventory, advisories, kev, nil)
	threatHits := make([]repository.ThreatHit, 0, len(hits))
	for _, h := range hits {
		threatHits = append(threatHits, threatHitFromMatch(h))
	}
	if err := deps.Threats.InsertHits(ctx, project.ID, threatHits); err != nil {
		return fmt.Errorf("insert hits: %w", err)
	}
	if deps.Queue != nil && deps.Notify != nil {
		NotifyForHits(ctx, deps.Queue, *deps.Notify, project.ID, threatHits, threatAdvisoryMeta(advisories, kev))
	}
	log.Info("threat sync project done", "hits", len(threatHits))
	return nil
}

func threatAdvisoryMeta(advisories []threats.Advisory, kev map[string]threats.KEVEntry) map[string]AdvisoryMeta {
	out := make(map[string]AdvisoryMeta, len(advisories))
	for _, a := range advisories {
		out[a.AdvisoryID] = AdvisoryMeta{
			AdvisoryID:  a.AdvisoryID,
			CVEID:       a.CVEID,
			Severity:    a.Severity,
			KEV:         threats.IsKEV(a.CVEID, a.Aliases, kev),
			AdvisoryURL: ThreatAdvisoryURL(a.AdvisoryID),
		}
	}
	return out
}

// threatHitFromMatch maps a matcher Hit to its persistence row: Evidence is
// JSON-marshaled, RuntimeStatus defaults to L0 (DB default), empty statuses
// fall back to declared/unconfirmed.
func threatHitFromMatch(h threats.Hit) repository.ThreatHit {
	var raw json.RawMessage
	if h.Evidence != nil {
		if b, err := json.Marshal(h.Evidence); err == nil {
			raw = b
		}
	}
	inventoryStatus := h.InventoryStatus
	if inventoryStatus == "" {
		inventoryStatus = threats.StatusDeclared
	}
	matchStatus := h.MatchStatus
	if matchStatus == "" {
		matchStatus = threats.MatchUnconfirmed
	}
	return repository.ThreatHit{
		AdvisoryID:      h.AdvisoryID,
		PkgName:         h.PkgName,
		PkgVersion:      h.PkgVersion,
		InventoryStatus: inventoryStatus,
		RuntimeStatus:   "L0",
		MatchStatus:     matchStatus,
		Evidence:        raw,
	}
}
