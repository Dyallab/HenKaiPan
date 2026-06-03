package events

import (
	"testing"

	"aspm/internal/assert"
)

func TestEventTypes_All(t *testing.T) {
	types := EventTypes()
	expected := []EventType{
		EventFindingSummaryCompleted,
		EventFindingValidationCompleted,
		EventScanCompleted,
		EventScanFailed,
		EventWebhookDelivered,
		EventWebhookFailed,
		EventRiskAcceptanceApproved,
		EventRiskAcceptanceRejected,
		EventPolicyViolation,
		EventScheduledTaskCompleted,
		EventNotificationCreated,
	}
	assert.Equal(t, len(types), len(expected))

	seen := make(map[EventType]bool)
	for _, et := range types {
		seen[et] = true
	}
	for _, et := range expected {
		if !seen[et] {
			t.Errorf("missing event type %q", et)
		}
	}
}

func TestEventType_String(t *testing.T) {
	tests := []struct {
		name  string
		input EventType
		want  string
	}{
		{"finding_summary", EventFindingSummaryCompleted, "finding_summary_completed"},
		{"scan_failed", EventScanFailed, "scan_failed"},
		{"policy_violation", EventPolicyViolation, "policy_violation"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.input.String(), tt.want)
		})
	}
}

func TestEventType_IsValid(t *testing.T) {
	t.Run("all_valid_types", func(t *testing.T) {
		for _, et := range EventTypes() {
			if !et.IsValid() {
				t.Errorf("expected %q to be valid", et)
			}
		}
	})

	t.Run("invalid_type", func(t *testing.T) {
		assert.False(t, EventType("invalid_type").IsValid())
	})

	t.Run("empty_type", func(t *testing.T) {
		assert.False(t, EventType("").IsValid())
	})
}

func TestValidateEventType(t *testing.T) {
	t.Run("valid_type", func(t *testing.T) {
		err := ValidateEventType("scan_completed")
		assert.Nil(t, err)
	})

	t.Run("invalid_type", func(t *testing.T) {
		err := ValidateEventType("bogus_type")
		assert.NotNil(t, err)
	})

	t.Run("invalid_type_message", func(t *testing.T) {
		err := ValidateEventType("unknown_event")
		if err == nil {
			t.Fatal("expected error")
		}
		assert.MatchesRegexp(t, err.Error(), "invalid event type.*unknown_event")
	})

	t.Run("empty_type", func(t *testing.T) {
		err := ValidateEventType("")
		assert.NotNil(t, err)
	})
}

func TestEvent_Creation(t *testing.T) {
	ev := Event{
		Type: EventScanCompleted,
		Data: ScanData{ScanID: "s-1", ProjectID: "p-1"},
		Metadata: EventMetadata{
			UserID:    "u-1",
			ProjectID: "p-1",
		},
	}
	assert.Equal(t, ev.Type, EventScanCompleted)
	assert.NotNil(t, ev.Data)
	assert.True(t, ev.CreatedAt.IsZero()) // zero if not explicitly set
}

func TestEventMetadata_Empty(t *testing.T) {
	m := EventMetadata{}
	assert.Equal(t, m.UserID, "")
	assert.Equal(t, m.ProjectID, "")
	assert.Equal(t, m.ScanID, "")
	assert.Equal(t, m.FindingID, "")
	assert.Nil(t, m.Tags)
}
