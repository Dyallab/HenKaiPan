package telemetry

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"aspm/internal/repository"

	"github.com/google/uuid"
)

type Client struct {
	instanceID string
	endpoint   string
	version    string
	tier      string
	store      repository.Stores
	httpClient *http.Client
}

type pingPayload struct {
	InstanceID string `json:"instance_id"`
	Version    string `json:"version"`
	Tier       string `json:"tier"`
	Projects   int    `json:"projects"`
	Users      int    `json:"users"`
	AIScans    int    `json:"ai_scans"`
	Timestamp  string `json:"timestamp"`
}

func NewClient(store repository.Stores, endpoint, version, tier string) *Client {
	return &Client{
		instanceID: loadOrGenerateInstanceID(),
		endpoint:   endpoint,
		version:    version,
		tier:       tier,
		store:      store,
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
}


func (c *Client) Start(ctx context.Context) {
	slog.Info("telemetry: starting daily ping",
		"instance_id", c.instanceID,
		"endpoint", c.endpoint)

	select {
	case <-time.After(10 * time.Minute):
		c.ping(ctx)
	case <-ctx.Done():
		return
	}

	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			c.ping(ctx)
		case <-ctx.Done():
			return
		}
	}
}

func (c *Client) ping(ctx context.Context) {
	payload, err := c.buildPayload(ctx)
	if err != nil {
		slog.Warn("telemetry: failed to build payload", "err", err)
		return
	}

	body, err := json.Marshal(payload)
	if err != nil {
		slog.Warn("telemetry: failed to marshal payload", "err", err)
		return
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.endpoint, bytes.NewReader(body))
	if err != nil {
		slog.Warn("telemetry: failed to build request", "err", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "HenKaiPan/"+c.version)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		slog.Warn("telemetry: ping failed", "err", err)
		return
	}
	resp.Body.Close()

	if resp.StatusCode >= 400 {
		slog.Warn("telemetry: ping rejected", "status", resp.StatusCode)
		return
	}

	slog.Debug("telemetry: ping sent",
		"projects", payload.Projects,
		"users", payload.Users,
		"ai_scans", payload.AIScans)
}

func (c *Client) buildPayload(ctx context.Context) (*pingPayload, error) {
	monthKey := time.Now().Format("2006-01")
	p := &pingPayload{
		InstanceID: c.instanceID,
		Version:    c.version,
		Tier:       c.tier,
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
	}

	if n, err := c.store.Apps.CountProjects(ctx); err == nil {
		p.Projects = n
	}
	if n, err := c.store.Users.Count(ctx); err == nil {
		p.Users = n
	}
	if n, err := c.store.Usage.GetAIScanCount(ctx, monthKey); err == nil {
		p.AIScans = n
	}

	return p, nil
}

func loadOrGenerateInstanceID() string {
	path := filepath.Join("data", "instance_id")
	if data, err := os.ReadFile(path); err == nil {
		id := string(bytes.TrimSpace(data))
		if id != "" {
			return id
		}
	}
	id := newUUID()
	if err := os.MkdirAll("data", 0755); err == nil {
		os.WriteFile(path, []byte(id), 0644)
	}
	return id
}

func newUUID() string {
	return uuid.New().String()
}
