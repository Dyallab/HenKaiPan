package events

import (
	"fmt"
)

// EventBuilder provides a fluent interface for creating events
type EventBuilder struct {
	eventType EventType
	data      interface{}
	metadata  EventMetadata
}

// NewEvent creates a new event builder
func NewEvent(eventType EventType) *EventBuilder {
	return &EventBuilder{
		eventType: eventType,
		metadata:  EventMetadata{},
	}
}

// WithData sets the event payload
func (b *EventBuilder) WithData(data interface{}) *EventBuilder {
	b.data = data
	return b
}

// WithUserID sets the user ID for scoped events
func (b *EventBuilder) WithUserID(userID string) *EventBuilder {
	b.metadata.UserID = userID
	return b
}

// WithProjectID sets the project ID for scoped events
func (b *EventBuilder) WithProjectID(projectID string) *EventBuilder {
	b.metadata.ProjectID = projectID
	return b
}

// WithFindingID sets the finding ID for scoped events
func (b *EventBuilder) WithFindingID(findingID string) *EventBuilder {
	b.metadata.FindingID = findingID
	return b
}

// WithScanID sets the scan ID for scoped events
func (b *EventBuilder) WithScanID(scanID string) *EventBuilder {
	b.metadata.ScanID = scanID
	return b
}

// WithTags adds metadata tags
func (b *EventBuilder) WithTags(tags map[string]string) *EventBuilder {
	b.metadata.Tags = tags
	return b
}

// Build creates the final event
func (b *EventBuilder) Build() Event {
	return Event{
		Type:     b.eventType,
		Data:     b.data,
		Metadata: b.metadata,
	}
}

// Publish builds and publishes the event
func (b *EventBuilder) Publish() {
	event := b.Build()
	Publish(event)
}

// Type-safe event constructors

// FindingSummaryData represents the payload for finding summary events
type FindingSummaryData struct {
	FindingID string `json:"finding_id"`
	Summary   string `json:"summary"`
}

// NewFindingSummaryCompleted creates a finding summary completed event
func NewFindingSummaryCompleted(findingID, summary string) *EventBuilder {
	return NewEvent(EventFindingSummaryCompleted).
		WithData(FindingSummaryData{
			FindingID: findingID,
			Summary:   summary,
		})
}

// FindingValidationData represents the payload for validation events
type FindingValidationData struct {
	FindingID  string  `json:"finding_id"`
	Confidence float64 `json:"confidence"`
	Reasoning  string  `json:"reasoning"`
	FPLikelihood string `json:"fp_likelihood"`
}

// NewFindingValidationCompleted creates a finding validation completed event
func NewFindingValidationCompleted(findingID string, confidence float64, reasoning, fpLikelihood string) *EventBuilder {
	return NewEvent(EventFindingValidationCompleted).
		WithData(FindingValidationData{
			FindingID:    findingID,
			Confidence:   confidence,
			Reasoning:    reasoning,
			FPLikelihood: fpLikelihood,
		})
}

// ScanData represents the payload for scan events
type ScanData struct {
	ScanID        string `json:"scan_id"`
	ProjectID     string `json:"project_id"`
	Scanner       string `json:"scanner"`
	FindingCount  int    `json:"finding_count"`
	Error         string `json:"error,omitempty"`
}

// NewScanCompleted creates a scan completed event
func NewScanCompleted(scanID, projectID, scanner string, findingCount int) *EventBuilder {
	return NewEvent(EventScanCompleted).
		WithData(ScanData{
			ScanID:       scanID,
			ProjectID:    projectID,
			Scanner:      scanner,
			FindingCount: findingCount,
		})
}

// NewScanFailed creates a scan failed event
func NewScanFailed(scanID, projectID, scanner, errorMsg string) *EventBuilder {
	return NewEvent(EventScanFailed).
		WithData(ScanData{
			ScanID:    scanID,
			ProjectID: projectID,
			Scanner:   scanner,
			Error:     errorMsg,
		})
}

// WebhookData represents the payload for webhook events
type WebhookData struct {
	WebhookID   string `json:"webhook_id"`
	DeliveryID  string `json:"delivery_id"`
	EventType   string `json:"event_type"`
	Success     bool   `json:"success"`
	StatusCode  int    `json:"status_code,omitempty"`
	Error       string `json:"error,omitempty"`
}

// NewWebhookDelivered creates a webhook delivered event
func NewWebhookDelivered(webhookID, deliveryID, eventType string, statusCode int) *EventBuilder {
	return NewEvent(EventWebhookDelivered).
		WithData(WebhookData{
			WebhookID:  webhookID,
			DeliveryID: deliveryID,
			EventType:  eventType,
			Success:    true,
			StatusCode: statusCode,
		})
}

// NewWebhookFailed creates a webhook failed event
func NewWebhookFailed(webhookID, deliveryID, eventType, errorMsg string) *EventBuilder {
	return NewEvent(EventWebhookFailed).
		WithData(WebhookData{
			WebhookID:  webhookID,
			DeliveryID: deliveryID,
			EventType:  eventType,
			Success:    false,
			Error:      errorMsg,
		})
}

// RiskAcceptanceData represents the payload for risk acceptance events
type RiskAcceptanceData struct {
	RiskAcceptanceID string `json:"risk_acceptance_id"`
	FindingID        string `json:"finding_id"`
	UserID           string `json:"user_id"`
	Status           string `json:"status"` // approved or rejected
	ReviewNotes      string `json:"review_notes,omitempty"`
}

// NewRiskAcceptanceApproved creates a risk acceptance approved event
func NewRiskAcceptanceApproved(riskID, findingID, userID, reviewNotes string) *EventBuilder {
	return NewEvent(EventRiskAcceptanceApproved).
		WithData(RiskAcceptanceData{
			RiskAcceptanceID: riskID,
			FindingID:        findingID,
			UserID:           userID,
			Status:           "approved",
			ReviewNotes:      reviewNotes,
		})
}

// NewRiskAcceptanceRejected creates a risk acceptance rejected event
func NewRiskAcceptanceRejected(riskID, findingID, userID, reviewNotes string) *EventBuilder {
	return NewEvent(EventRiskAcceptanceRejected).
		WithData(RiskAcceptanceData{
			RiskAcceptanceID: riskID,
			FindingID:        findingID,
			UserID:           userID,
			Status:           "rejected",
			ReviewNotes:      reviewNotes,
		})
}

// PolicyViolationData represents the payload for policy violation events
type PolicyViolationData struct {
	PolicyID   string `json:"policy_id"`
	PolicyName string `json:"policy_name"`
	FindingID  string `json:"finding_id"`
	UserID     string `json:"user_id"`
	Action     string `json:"action"` // what action was taken
}

// NewPolicyViolation creates a policy violation event
func NewPolicyViolation(policyID, policyName, findingID, userID, action string) *EventBuilder {
	return NewEvent(EventPolicyViolation).
		WithData(PolicyViolationData{
			PolicyID:   policyID,
			PolicyName: policyName,
			FindingID:  findingID,
			UserID:     userID,
			Action:     action,
		})
}

// ScheduledTaskData represents the payload for scheduled task events
type ScheduledTaskData struct {
	ScheduleID string `json:"schedule_id"`
	TaskType   string `json:"task_type"`
	ProjectID  string `json:"project_id"`
	Success    bool   `json:"success"`
	Error      string `json:"error,omitempty"`
}

// NewScheduledTaskCompleted creates a scheduled task completed event
func NewScheduledTaskCompleted(scheduleID, taskType, projectID string) *EventBuilder {
	return NewEvent(EventScheduledTaskCompleted).
		WithData(ScheduledTaskData{
			ScheduleID: scheduleID,
			TaskType:   taskType,
			ProjectID:  projectID,
			Success:    true,
		})
}

// NotificationCreatedData represents the payload for notification events
type NotificationCreatedData struct {
	NotificationID string `json:"notification_id"`
	UserID         string `json:"user_id"`
	Title          string `json:"title"`
	Type           string `json:"type"`
	EntityType     string `json:"entity_type,omitempty"`
	EntityID       string `json:"entity_id,omitempty"`
}

// NewNotificationCreated creates a notification created event
func NewNotificationCreated(notificationID, userID, title, notifType, entityType, entityID string) *EventBuilder {
	return NewEvent(EventNotificationCreated).
		WithData(NotificationCreatedData{
			NotificationID: notificationID,
			UserID:         userID,
			Title:          title,
			Type:           notifType,
			EntityType:     entityType,
			EntityID:       entityID,
		})
}

// ValidateEventType checks if an event type string is valid
func ValidateEventType(eventType string) error {
	for _, valid := range EventTypes() {
		if string(valid) == eventType {
			return nil
		}
	}
	return fmt.Errorf("invalid event type: %s", eventType)
}
