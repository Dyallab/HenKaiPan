package events

import (
	"testing"

	"aspm/internal/assert"
)

func TestNewEvent_BuilderChaining(t *testing.T) {
	b := NewEvent(EventScanCompleted).
		WithData("payload").
		WithUserID("u-1").
		WithProjectID("p-1").
		WithFindingID("f-1").
		WithScanID("s-1").
		WithTags(map[string]string{"env": "prod"})

	ev := b.Build()
	assert.Equal(t, ev.Type, EventScanCompleted)
	assert.NotNil(t, ev.Data)
	assert.Equal(t, ev.Metadata.UserID, "u-1")
	assert.Equal(t, ev.Metadata.ProjectID, "p-1")
	assert.Equal(t, ev.Metadata.FindingID, "f-1")
	assert.Equal(t, ev.Metadata.ScanID, "s-1")
	assert.Equal(t, len(ev.Metadata.Tags), 1)
	assert.Equal(t, ev.Metadata.Tags["env"], "prod")
}

func TestNewEvent_EmptyBuilder(t *testing.T) {
	b := NewEvent(EventScanFailed)
	ev := b.Build()
	assert.Equal(t, ev.Type, EventScanFailed)
	assert.Nil(t, ev.Data)
}

func TestNewEvent_WithTagsNil(t *testing.T) {
	b := NewEvent(EventPolicyViolation).WithTags(nil)
	ev := b.Build()
	assert.Nil(t, ev.Metadata.Tags)
}

func TestNewEvent_WithTagsEmpty(t *testing.T) {
	b := NewEvent(EventPolicyViolation).WithTags(map[string]string{})
	ev := b.Build()
	assert.Equal(t, len(ev.Metadata.Tags), 0)
}

func TestNewEvent_DataOverride(t *testing.T) {
	b := NewEvent(EventScanCompleted).WithData("first").WithData("second")
	ev := b.Build()
	assert.Equal(t, ev.Data, "second")
}

// Type-safe constructors

func TestNewEvent_Constructors(t *testing.T) {
	t.Run("FindingSummaryCompleted", func(t *testing.T) {
		b := NewFindingSummaryCompleted("f-1", "summary text")
		ev := b.Build()
		assert.Equal(t, ev.Type, EventFindingSummaryCompleted)
		d, ok := ev.Data.(FindingSummaryData)
		if !ok {
			t.Fatal("expected FindingSummaryData")
		}
		assert.Equal(t, d.FindingID, "f-1")
		assert.Equal(t, d.Summary, "summary text")
	})

	t.Run("FindingValidationCompleted", func(t *testing.T) {
		b := NewFindingValidationCompleted("f-1", 0.95, "looks good", "low")
		ev := b.Build()
		assert.Equal(t, ev.Type, EventFindingValidationCompleted)
		d, ok := ev.Data.(FindingValidationData)
		if !ok {
			t.Fatal("expected FindingValidationData")
		}
		assert.Equal(t, d.FindingID, "f-1")
		assert.Equal(t, d.Confidence, 0.95)
		assert.Equal(t, d.Reasoning, "looks good")
		assert.Equal(t, d.FPLikelihood, "low")
	})

	t.Run("ScanCompleted", func(t *testing.T) {
		b := NewScanCompleted("s-1", "p-1", "semgrep", 42)
		ev := b.Build()
		assert.Equal(t, ev.Type, EventScanCompleted)
		d, ok := ev.Data.(ScanData)
		if !ok {
			t.Fatal("expected ScanData")
		}
		assert.Equal(t, d.ScanID, "s-1")
		assert.Equal(t, d.ProjectID, "p-1")
		assert.Equal(t, d.Scanner, "semgrep")
		assert.Equal(t, d.FindingCount, 42)
		assert.Equal(t, d.Error, "")
	})

	t.Run("ScanFailed", func(t *testing.T) {
		b := NewScanFailed("s-1", "p-1", "trivy", "timeout")
		ev := b.Build()
		assert.Equal(t, ev.Type, EventScanFailed)
		d, ok := ev.Data.(ScanData)
		if !ok {
			t.Fatal("expected ScanData")
		}
		assert.Equal(t, d.ScanID, "s-1")
		assert.Equal(t, d.Error, "timeout")
	})

	t.Run("WebhookDelivered", func(t *testing.T) {
		b := NewWebhookDelivered("wh-1", "d-1", "scan.completed", 200)
		ev := b.Build()
		assert.Equal(t, ev.Type, EventWebhookDelivered)
		d, ok := ev.Data.(WebhookData)
		if !ok {
			t.Fatal("expected WebhookData")
		}
		assert.Equal(t, d.WebhookID, "wh-1")
		assert.Equal(t, d.DeliveryID, "d-1")
		assert.Equal(t, d.EventType, "scan.completed")
		assert.True(t, d.Success)
		assert.Equal(t, d.StatusCode, 200)
	})

	t.Run("WebhookFailed", func(t *testing.T) {
		b := NewWebhookFailed("wh-1", "d-1", "scan.completed", "connection refused")
		ev := b.Build()
		assert.Equal(t, ev.Type, EventWebhookFailed)
		d, ok := ev.Data.(WebhookData)
		if !ok {
			t.Fatal("expected WebhookData")
		}
		assert.Equal(t, d.WebhookID, "wh-1")
		assert.False(t, d.Success)
		assert.Equal(t, d.Error, "connection refused")
	})

	t.Run("RiskAcceptanceApproved", func(t *testing.T) {
		b := NewRiskAcceptanceApproved("ra-1", "f-1", "u-1", "looks fine")
		ev := b.Build()
		assert.Equal(t, ev.Type, EventRiskAcceptanceApproved)
		d, ok := ev.Data.(RiskAcceptanceData)
		if !ok {
			t.Fatal("expected RiskAcceptanceData")
		}
		assert.Equal(t, d.RiskAcceptanceID, "ra-1")
		assert.Equal(t, d.Status, "approved")
		assert.Equal(t, d.ReviewNotes, "looks fine")
	})

	t.Run("RiskAcceptanceRejected", func(t *testing.T) {
		b := NewRiskAcceptanceRejected("ra-1", "f-1", "u-1", "needs more info")
		ev := b.Build()
		assert.Equal(t, ev.Type, EventRiskAcceptanceRejected)
		d, ok := ev.Data.(RiskAcceptanceData)
		if !ok {
			t.Fatal("expected RiskAcceptanceData")
		}
		assert.Equal(t, d.Status, "rejected")
	})

	t.Run("PolicyViolation", func(t *testing.T) {
		b := NewPolicyViolation("pol-1", "No HTTP", "f-1", "u-1", "blocked")
		ev := b.Build()
		assert.Equal(t, ev.Type, EventPolicyViolation)
		d, ok := ev.Data.(PolicyViolationData)
		if !ok {
			t.Fatal("expected PolicyViolationData")
		}
		assert.Equal(t, d.PolicyID, "pol-1")
		assert.Equal(t, d.PolicyName, "No HTTP")
		assert.Equal(t, d.Action, "blocked")
	})

	t.Run("ScheduledTaskCompleted", func(t *testing.T) {
		b := NewScheduledTaskCompleted("sch-1", "scan", "p-1")
		ev := b.Build()
		assert.Equal(t, ev.Type, EventScheduledTaskCompleted)
		d, ok := ev.Data.(ScheduledTaskData)
		if !ok {
			t.Fatal("expected ScheduledTaskData")
		}
		assert.Equal(t, d.ScheduleID, "sch-1")
		assert.Equal(t, d.TaskType, "scan")
		assert.True(t, d.Success)
	})

	t.Run("NotificationCreated", func(t *testing.T) {
		b := NewNotificationCreated("n-1", "u-1", "Scan complete", "info", "scan", "s-1")
		ev := b.Build()
		assert.Equal(t, ev.Type, EventNotificationCreated)
		d, ok := ev.Data.(NotificationCreatedData)
		if !ok {
			t.Fatal("expected NotificationCreatedData")
		}
		assert.Equal(t, d.NotificationID, "n-1")
		assert.Equal(t, d.UserID, "u-1")
		assert.Equal(t, d.Title, "Scan complete")
		assert.Equal(t, d.Type, "info")
		assert.Equal(t, d.EntityType, "scan")
		assert.Equal(t, d.EntityID, "s-1")
	})
}

func TestValidateEventType_AllValid(t *testing.T) {
	for _, et := range EventTypes() {
		t.Run(string(et), func(t *testing.T) {
			err := ValidateEventType(string(et))
			assert.Nil(t, err)
		})
	}
}
