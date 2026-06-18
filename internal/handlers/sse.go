package handlers

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"aspm/internal/auth"
	"aspm/internal/events"
)

const sseHeartbeatInterval = 30 * time.Second

// HandleSSEEvents handles Server-Sent Events stream
func (h *Handler) HandleSSEEvents(w http.ResponseWriter, r *http.Request) {
	flusher, canFlush := w.(http.Flusher)

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	var filters []events.EventType
	if types := r.URL.Query().Get("types"); types != "" {
		for _, t := range strings.Split(types, ",") {
			t = strings.TrimSpace(t)
			if events.EventType(t).IsValid() {
				filters = append(filters, events.EventType(t))
			}
		}
	}

	var userID, projectID string
	if claims := auth.GetClaims(r); claims != nil {
		userID = claims.UserID
		projectID = r.URL.Query().Get("project_id")
	}

	if userID != "" && events.UserConnectionCount(userID) >= 5 {
		slog.Warn("SSE connection limit reached", "user_id", userID)
		http.Error(w, `{"error":"connection_limit_reached"}`, http.StatusTooManyRequests)
		return
	}

	clientID := fmt.Sprintf("%s-%d", userID, time.Now().UnixNano())

	eventChan, cleanup := events.SubscribeWithScope(r.Context(), clientID, userID, projectID, filters...)
	defer cleanup()

	slog.Debug("SSE client connected",
		"client_id", clientID,
		"user_id", userID,
		"project_id", projectID,
		"filters", len(filters))

	fmt.Fprintf(w, "event: connected\ndata: {\"client_id\":\"%s\",\"connected_at\":\"%s\"}\n\n",
		clientID, time.Now().Format(time.RFC3339))
	if canFlush {
		flusher.Flush()
	}

	heartbeat := time.NewTicker(sseHeartbeatInterval)
	defer heartbeat.Stop()

	for {
		select {
		case <-r.Context().Done():
			slog.Debug("SSE client disconnected", "client_id", clientID)
			return
		case <-heartbeat.C:
			fmt.Fprint(w, ": heartbeat\n\n")
			if canFlush {
				flusher.Flush()
			}
		case event, ok := <-eventChan:
			if !ok {
				return
			}

			data, err := json.Marshal(event)
			if err != nil {
				slog.Warn("Failed to marshal SSE event", "err", err)
				continue
			}

			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event.Type, data)
			if canFlush {
				flusher.Flush()
			}
		}
	}
}

// GetSSEStats returns statistics about SSE connections
func (h *Handler) GetSSEStats(w http.ResponseWriter, r *http.Request) {
	stats := events.GetClientStats()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}