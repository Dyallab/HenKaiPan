package tasks

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"

	"aspm/internal/models"
	"aspm/internal/repository"

	"github.com/hibiken/asynq"
)

type notifyTaskCatcher struct {
	mu    sync.Mutex
	tasks []*asynq.Task
}

func (f *notifyTaskCatcher) EnqueueContext(_ context.Context, task *asynq.Task, _ ...asynq.Option) (*asynq.TaskInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tasks = append(f.tasks, task)
	return nil, nil
}

func (f *notifyTaskCatcher) countByType() map[string]int {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[string]int{}
	for _, t := range f.tasks {
		out[t.Type()]++
	}
	return out
}

func (f *notifyTaskCatcher) firstByType(typ string) *asynq.Task {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, t := range f.tasks {
		if t.Type() == typ {
			return t
		}
	}
	return nil
}

type fakeNotifyWebhooks struct {
	webhooks []models.Webhook
}

func (f *fakeNotifyWebhooks) ListEnabled(_ context.Context) ([]models.Webhook, error) {
	return f.webhooks, nil
}

type fakeNotifySettings struct {
	recipients []string
}

func (f *fakeNotifySettings) GetNotificationSettings(_ context.Context) (*models.NotificationSettings, error) {
	return &models.NotificationSettings{EmailRecipients: f.recipients}, nil
}

type fakeNotifyScans struct {
	mu       sync.Mutex
	inserted []fakeScanInsert
}

type fakeScanInsert struct {
	Target    string
	Scanner   string
	BatchID   string
	ProjectID string
}

func (f *fakeNotifyScans) Insert(_ context.Context, target, scanner, batchID string, projectID *string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	pid := ""
	if projectID != nil {
		pid = *projectID
	}
	f.inserted = append(f.inserted, fakeScanInsert{Target: target, Scanner: scanner, BatchID: batchID, ProjectID: pid})
	return "scan-test-1", nil
}

func notifyTestDeps() (ThreatNotifyDeps, *notifyTaskCatcher) {
	catcher := &notifyTaskCatcher{}
	deps := ThreatNotifyDeps{
		Webhooks: &fakeNotifyWebhooks{webhooks: []models.Webhook{
			{ID: "wh-1", Label: "sec", Events: []string{ThreatKEVEvent}, Enabled: true},
		}},
		Settings:             &fakeNotifySettings{recipients: []string{"sec@example.com"}},
		Scans:                &fakeNotifyScans{},
		Email:                EmailConfig{Enabled: true, From: "noreply@example.com"},
		NotificationsEnabled: true,
		RescanScanner:        "osv-scanner",
		ProjectTarget: func(_ context.Context, projectID string) (string, bool) {
			return "https://github.com/example/repo.git", true
		},
	}
	return deps, catcher
}

func kevAdvisories() map[string]AdvisoryMeta {
	return map[string]AdvisoryMeta{
		"GHSA-test-1": {
			AdvisoryID:  "GHSA-test-1",
			CVEID:       "CVE-2021-44228",
			Severity:    "CRITICAL",
			KEV:         true,
			AdvisoryURL: "https://osv.dev/vulnerability/GHSA-test-1",
		},
	}
}

func TestThreatNotify_KEVActiveThreatEnqueues(t *testing.T) {
	deps, catcher := notifyTestDeps()
	hits := []repository.ThreatHit{{
		AdvisoryID:  "GHSA-test-1",
		PkgName:     "log4j",
		PkgVersion:  "2.14.0",
		MatchStatus: "active_threat",
	}}

	NotifyForHits(context.Background(), catcher, deps, "proj-1", hits, kevAdvisories())

	counts := catcher.countByType()
	if counts[TypeWebhookSend] != 1 {
		t.Fatalf("webhook:send enqueued = %d, want 1 (all=%v)", counts[TypeWebhookSend], counts)
	}
	if counts[TypeEmailSend] != 1 {
		t.Fatalf("email:send enqueued = %d, want 1 (all=%v)", counts[TypeEmailSend], counts)
	}
	if counts[TypeScanRun] != 0 {
		t.Fatalf("scan:run enqueued = %d, want 0 (all=%v)", counts[TypeScanRun], counts)
	}

	wt := catcher.firstByType(TypeWebhookSend)
	wp, err := UnmarshalWebhookPayload(wt.Payload())
	if err != nil {
		t.Fatalf("unmarshal webhook payload: %v", err)
	}
	if wp.EventType != ThreatKEVEvent || wp.WebhookID != "wh-1" {
		t.Fatalf("unexpected webhook task payload: %+v", wp)
	}
	var env WebhookEventEnvelope
	if err := json.Unmarshal(wp.Payload, &env); err != nil {
		t.Fatalf("unmarshal webhook envelope: %v", err)
	}
	data, _ := json.Marshal(env.Data)
	if !strings.Contains(string(data), "https://osv.dev/vulnerability/GHSA-test-1") {
		t.Fatalf("webhook event missing advisory link: %s", data)
	}

	et := catcher.firstByType(TypeEmailSend)
	var ep EmailSendPayload
	if err := json.Unmarshal(et.Payload(), &ep); err != nil {
		t.Fatalf("unmarshal email payload: %v", err)
	}
	if len(ep.To) != 1 || ep.To[0] != "sec@example.com" {
		t.Fatalf("email recipients = %v, want [sec@example.com]", ep.To)
	}
	if !strings.Contains(ep.Body, "https://osv.dev/vulnerability/GHSA-test-1") || !strings.Contains(ep.Body, "CVE-2021-44228") {
		t.Fatalf("email body missing advisory link/cve: %q", ep.Body)
	}
}

func TestThreatNotify_UnconfirmedEnqueuesRescanOnly(t *testing.T) {
	deps, catcher := notifyTestDeps()
	hits := []repository.ThreatHit{{
		AdvisoryID:  "GHSA-test-1",
		PkgName:     "log4j",
		PkgVersion:  "2.14.0",
		MatchStatus: "unconfirmed",
	}}

	NotifyForHits(context.Background(), catcher, deps, "proj-1", hits, kevAdvisories())

	counts := catcher.countByType()
	if counts[TypeScanRun] != 1 {
		t.Fatalf("scan:run enqueued = %d, want 1 (all=%v)", counts[TypeScanRun], counts)
	}
	if counts[TypeWebhookSend] != 0 || counts[TypeEmailSend] != 0 {
		t.Fatalf("zero notifies expected for unconfirmed, got %v", counts)
	}

	st := catcher.firstByType(TypeScanRun)
	sp, err := UnmarshalScanPayload(st.Payload())
	if err != nil {
		t.Fatalf("unmarshal scan payload: %v", err)
	}
	if sp.ProjectID != "proj-1" || sp.Target != "https://github.com/example/repo.git" || sp.Scanner != "osv-scanner" || sp.ScanID != "scan-test-1" {
		t.Fatalf("unexpected scan payload: %+v", sp)
	}
}

func TestThreatNotify_OptOutSuppressesNotifiesKeepsRescan(t *testing.T) {
	deps, catcher := notifyTestDeps()
	deps.NotificationsEnabled = false
	hits := []repository.ThreatHit{
		{AdvisoryID: "GHSA-test-1", PkgName: "log4j", PkgVersion: "2.14.0", MatchStatus: "active_threat"},
		{AdvisoryID: "GHSA-test-1", PkgName: "log4j", PkgVersion: "2.14.0", MatchStatus: "unconfirmed"},
	}

	NotifyForHits(context.Background(), catcher, deps, "proj-1", hits, kevAdvisories())

	counts := catcher.countByType()
	if counts[TypeWebhookSend] != 0 || counts[TypeEmailSend] != 0 {
		t.Fatalf("opt-out must suppress all notifies, got %v", counts)
	}
	if counts[TypeScanRun] != 1 {
		t.Fatalf("silent rescan must still enqueue with opt-out, got %v", counts)
	}
}

func TestThreatNotify_NonKEVActiveThreatSilent(t *testing.T) {
	deps, catcher := notifyTestDeps()
	hits := []repository.ThreatHit{{
		AdvisoryID:  "GHSA-test-1",
		PkgName:     "log4j",
		PkgVersion:  "2.14.0",
		MatchStatus: "active_threat",
	}}
	advs := kevAdvisories()
	advs["GHSA-test-1"] = AdvisoryMeta{
		AdvisoryID:  "GHSA-test-1",
		CVEID:       "CVE-2021-44228",
		Severity:    "HIGH",
		AdvisoryURL: "https://osv.dev/vulnerability/GHSA-test-1",
	}

	NotifyForHits(context.Background(), catcher, deps, "proj-1", hits, advs)

	if counts := catcher.countByType(); len(counts) != 0 {
		t.Fatalf("non-KEV active_threat must enqueue nothing, got %v", counts)
	}
}
