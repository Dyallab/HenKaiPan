package events

// FindingSummaryData represents the payload for finding summary events
type FindingSummaryData struct {
	FindingID string `json:"finding_id"`
	Summary   string `json:"summary"`
}

// NewFindingSummaryCompleted creates a finding summary completed event
func NewFindingSummaryCompleted(findingID, summary string) Event {
	return Event{
		Type: EventFindingSummaryCompleted,
		Data: FindingSummaryData{FindingID: findingID, Summary: summary},
		Metadata: EventMetadata{FindingID: findingID},
	}
}

// FindingValidationData represents the payload for validation events
type FindingValidationData struct {
	FindingID    string  `json:"finding_id"`
	Confidence   float64 `json:"confidence"`
	Reasoning    string  `json:"reasoning"`
	FPLikelihood string  `json:"fp_likelihood"`
}

// NewFindingValidationCompleted creates a finding validation completed event
func NewFindingValidationCompleted(findingID string, confidence float64, reasoning, fpLikelihood string) Event {
	return Event{
		Type: EventFindingValidationCompleted,
		Data: FindingValidationData{
			FindingID:    findingID,
			Confidence:   confidence,
			Reasoning:    reasoning,
			FPLikelihood: fpLikelihood,
		},
		Metadata: EventMetadata{FindingID: findingID},
	}
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
func NewScanCompleted(scanID, projectID, scanner string, findingCount int) Event {
	return Event{
		Type: EventScanCompleted,
		Data: ScanData{ScanID: scanID, ProjectID: projectID, Scanner: scanner, FindingCount: findingCount},
	}
}

// NewScanFailed creates a scan failed event
func NewScanFailed(scanID, projectID, scanner, errorMsg string) Event {
	return Event{
		Type: EventScanFailed,
		Data: ScanData{ScanID: scanID, ProjectID: projectID, Scanner: scanner, Error: errorMsg},
	}
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
func NewWebhookDelivered(webhookID, deliveryID, eventType string, statusCode int) Event {
	return Event{
		Type: EventWebhookDelivered,
		Data: WebhookData{WebhookID: webhookID, DeliveryID: deliveryID, EventType: eventType, Success: true, StatusCode: statusCode},
	}
}

// NewWebhookFailed creates a webhook failed event
func NewWebhookFailed(webhookID, deliveryID, eventType, errorMsg string) Event {
	return Event{
		Type: EventWebhookFailed,
		Data: WebhookData{WebhookID: webhookID, DeliveryID: deliveryID, EventType: eventType, Success: false, Error: errorMsg},
	}
}

// RiskAcceptanceData represents the payload for risk acceptance events
type RiskAcceptanceData struct {
	RiskAcceptanceID string `json:"risk_acceptance_id"`
	FindingID        string `json:"finding_id"`
	UserID           string `json:"user_id"`
	Status           string `json:"status"`
	ReviewNotes      string `json:"review_notes,omitempty"`
}

// NewRiskAcceptanceApproved creates a risk acceptance approved event
func NewRiskAcceptanceApproved(riskID, findingID, userID, reviewNotes string) Event {
	return Event{
		Type: EventRiskAcceptanceApproved,
		Data: RiskAcceptanceData{RiskAcceptanceID: riskID, FindingID: findingID, UserID: userID, Status: "approved", ReviewNotes: reviewNotes},
	}
}

// NewRiskAcceptanceRejected creates a risk acceptance rejected event
func NewRiskAcceptanceRejected(riskID, findingID, userID, reviewNotes string) Event {
	return Event{
		Type: EventRiskAcceptanceRejected,
		Data: RiskAcceptanceData{RiskAcceptanceID: riskID, FindingID: findingID, UserID: userID, Status: "rejected", ReviewNotes: reviewNotes},
	}
}

// PolicyViolationData represents the payload for policy violation events
type PolicyViolationData struct {
	PolicyID   string `json:"policy_id"`
	PolicyName string `json:"policy_name"`
	FindingID  string `json:"finding_id"`
	UserID     string `json:"user_id"`
	Action     string `json:"action"`
}

// NewPolicyViolation creates a policy violation event
func NewPolicyViolation(policyID, policyName, findingID, userID, action string) Event {
	return Event{
		Type: EventPolicyViolation,
		Data: PolicyViolationData{PolicyID: policyID, PolicyName: policyName, FindingID: findingID, UserID: userID, Action: action},
	}
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
func NewScheduledTaskCompleted(scheduleID, taskType, projectID string) Event {
	return Event{
		Type: EventScheduledTaskCompleted,
		Data: ScheduledTaskData{ScheduleID: scheduleID, TaskType: taskType, ProjectID: projectID, Success: true},
	}
}

// NotificationCreatedData represents the payload for notification events
type NotificationCreatedData struct {
	NotificationID string `json:"notification_id"`
	UserID         string `json:"user_id"`
	Title          string `json:"title"`
	Type           string `json:"type"`
	EntityType     string `json:"entity_type,omitempty"`
	EntityID       string `json:"entity_id,omitempty"`
	AISummary      string `json:"ai_summary,omitempty"`
}

// NewNotificationCreated creates a notification created event
func NewNotificationCreated(notificationID, userID, title, notifType, entityType, entityID, aiSummary string) Event {
	return Event{
		Type: EventNotificationCreated,
		Data: NotificationCreatedData{
			NotificationID: notificationID,
			UserID:         userID,
			Title:          title,
			Type:           notifType,
			EntityType:     entityType,
			EntityID:       entityID,
			AISummary:      aiSummary,
		},
		Metadata: EventMetadata{UserID: userID},
	}
}
