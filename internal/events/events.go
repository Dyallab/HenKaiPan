package events

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// EventType represents a specific type of SSE event
type EventType string

const (
	// Finding events
	EventFindingSummaryCompleted    EventType = "finding_summary_completed"
	EventFindingValidationCompleted EventType = "finding_validation_completed"
	
	// Scan events
	EventScanCompleted EventType = "scan_completed"
	EventScanFailed    EventType = "scan_failed"
	
	// Webhook events
	EventWebhookDelivered EventType = "webhook_delivered"
	EventWebhookFailed    EventType = "webhook_failed"
	
	// Risk acceptance events
	EventRiskAcceptanceApproved EventType = "risk_acceptance_approved"
	EventRiskAcceptanceRejected EventType = "risk_acceptance_rejected"
	
	// Policy events
	EventPolicyViolation EventType = "policy_violation"
	
	// Schedule events
	EventScheduledTaskCompleted EventType = "scheduled_task_completed"

	// Notification events
	EventNotificationCreated EventType = "notification_created"
)

// EventTypes returns all available event types
func EventTypes() []EventType {
	return []EventType{
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
}

// String returns the string representation of EventType
func (t EventType) String() string {
	return string(t)
}

// IsValid checks if the event type is recognized
func (t EventType) IsValid() bool {
	for _, valid := range EventTypes() {
		if t == valid {
			return true
		}
	}
	return false
}

// EventMetadata contains optional metadata for event filtering/scoping
type EventMetadata struct {
	UserID    string            `json:"user_id,omitempty"`
	ProjectID string            `json:"project_id,omitempty"`
	ScanID    string            `json:"scan_id,omitempty"`
	FindingID string            `json:"finding_id,omitempty"`
	Tags      map[string]string `json:"tags,omitempty"`
}

// Event represents a server-sent event with type-safe payload
type Event struct {
	Type      EventType   `json:"type"`
	Data      interface{} `json:"data"`
	Metadata  EventMetadata `json:"metadata,omitempty"`
	CreatedAt time.Time   `json:"created_at"`
}

// Client represents a connected SSE client
type Client struct {
	id       string
	events   chan<- Event
	done     <-chan struct{}
	filters  map[EventType]bool // if empty, receives all events
	userID   string             // for user-scoped events
	projectID string            // for project-scoped events
}

const maxConnectionsPerUser = 5
type Hub struct {
	mu         sync.RWMutex
	clients    map[string]*Client
	register   chan *Client
	unregister chan string
	events     chan Event
	broadcast  chan Event // for broadcasting to all clients
}

var hub *Hub
var once sync.Once

// GetHub returns the singleton hub instance
func GetHub() *Hub {
	once.Do(func() {
		hub = &Hub{
			clients:    make(map[string]*Client),
			register:   make(chan *Client, 100),
			unregister: make(chan string, 100),
			events:     make(chan Event, 100),
			broadcast:  make(chan Event, 100),
		}
		go hub.run()
	})
	return hub
}

func (h *Hub) run() {
	for {
		select {
		case client := <-h.register:
			h.mu.Lock()
			if client.userID != "" {
				count := 0
				for _, c := range h.clients {
					if c.userID == client.userID {
						count++
					}
				}
				if count >= maxConnectionsPerUser {
					close(client.events)
					h.mu.Unlock()
					slog.Warn("SSE connection limit reached for user",
						"user_id", client.userID,
						"limit", maxConnectionsPerUser)
					continue
				}
			}
			h.clients[client.id] = client
			h.mu.Unlock()

		case clientID := <-h.unregister:
			h.mu.Lock()
			if client, ok := h.clients[clientID]; ok {
				close(client.events)
				delete(h.clients, clientID)
			}
			h.mu.Unlock()

		case event := <-h.events:
			h.dispatchToClients(event)

		case event := <-h.broadcast:
			h.dispatchToClients(event)
		}
	}
}

func (h *Hub) dispatchToClients(event Event) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	for _, client := range h.clients {
		// Apply filters
		if !h.matchesFilters(client, event) {
			continue
		}

		// Apply scoping
		if !h.matchesScope(client, event) {
			continue
		}

		// Try to send, skip if buffer full
		select {
		case client.events <- event:
		default:
			// Client buffer full, log warning
			slog.Warn("SSE client buffer full, skipping event", 
				"client_id", client.id, 
				"event_type", event.Type)
		}
	}
}

func (h *Hub) matchesFilters(client *Client, event Event) bool {
	// No filters = receive all
	if len(client.filters) == 0 {
		return true
	}
	_, matches := client.filters[event.Type]
	return matches
}

func (h *Hub) matchesScope(client *Client, event Event) bool {
	// User scoping
	if client.userID != "" && event.Metadata.UserID != "" {
		if client.userID != event.Metadata.UserID {
			return false
		}
	}

	// Project scoping
	if client.projectID != "" && event.Metadata.ProjectID != "" {
		if client.projectID != event.Metadata.ProjectID {
			return false
		}
	}

	return true
}

// Publish sends an event to all connected clients and broadcasts it via Redis
// so that other processes (e.g., API server) can deliver it to their SSE clients.
func Publish(event Event) {
	if event.CreatedAt.IsZero() {
		event.CreatedAt = time.Now()
	}
	GetHub().events <- event
	PublishToRedis(event)
}

// Broadcast sends an event to all clients without filtering
func Broadcast(event Event) {
	if event.CreatedAt.IsZero() {
		event.CreatedAt = time.Now()
	}
	GetHub().broadcast <- event
}

// Subscribe creates a new SSE client connection
// filters: if provided, only receive events of those types. If nil/empty, receive all.
func Subscribe(ctx context.Context, clientID string, filters ...EventType) (<-chan Event, func()) {
	return SubscribeWithScope(ctx, clientID, "", "", filters...)
}

// SubscribeWithScope creates a scoped SSE client connection
func SubscribeWithScope(ctx context.Context, clientID, userID, projectID string, filters ...EventType) (<-chan Event, func()) {
	h := GetHub()
	events := make(chan Event, 50)
	done := make(chan struct{})

	client := &Client{
		id:        clientID,
		events:    events,
		done:      done,
		filters:   make(map[EventType]bool),
		userID:    userID,
		projectID: projectID,
	}

	for _, f := range filters {
		client.filters[f] = true
	}

	h.register <- client

	var cleanupOnce sync.Once
	cleanup := func() {
		cleanupOnce.Do(func() {
			close(done)
			h.unregister <- clientID
		})
	}

	// Handle context cancellation
	go func() {
		<-ctx.Done()
		cleanup()
	}()

	return events, cleanup
}

// ClientCount returns the number of connected clients
func ClientCount() int {
	h := GetHub()
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.clients)
}

// UserConnectionCount returns the number of active SSE connections for a user
func UserConnectionCount(userID string) int {
	if userID == "" {
		return 0
	}
	h := GetHub()
	h.mu.RLock()
	defer h.mu.RUnlock()
	count := 0
	for _, c := range h.clients {
		if c.userID == userID {
			count++
		}
	}
	return count
}

// GetClientStats returns statistics about connected clients
func GetClientStats() map[string]interface{} {
	h := GetHub()
	h.mu.RLock()
	defer h.mu.RUnlock()

	stats := map[string]interface{}{
		"total_clients": len(h.clients),
		"by_type":       make(map[EventType]int),
	}

	// Count clients by filter type
	typeCounts := make(map[EventType]int)
	for _, client := range h.clients {
		if len(client.filters) == 0 {
			typeCounts["*"]++
		} else {
			for eventType := range client.filters {
				typeCounts[eventType]++
			}
		}
	}

	stats["by_type"] = typeCounts
	return stats
}
