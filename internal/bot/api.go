package bot

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// APIClient communicates with the HenKaiPan API for triage actions.
type APIClient struct {
	baseURL   string
	apiToken  string
	httpClient *http.Client
}

// NewAPIClient creates a new APIClient.
func NewAPIClient(baseURL, apiToken string) *APIClient {
	return &APIClient{
		baseURL:  baseURL,
		apiToken: apiToken,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// UpdateFindingStatus updates the status of a finding (e.g. "in_review", "accepted_risk").
func (c *APIClient) UpdateFindingStatus(ctx context.Context, findingID, status string) error {
	return c.patchFinding(ctx, findingID, findingStatusUpdatePayload{Status: status})
}

// UpdateFindingAssignee assigns a user to a finding.
func (c *APIClient) UpdateFindingAssignee(ctx context.Context, findingID, assignee string) error {
	return c.patchFinding(ctx, findingID, findingStatusUpdatePayload{AssignedTo: assignee})
}

// ListUsers retrieves all users from the API.
func (c *APIClient) ListUsers(ctx context.Context) ([]User, error) {
	u := c.baseURL + "/api/users"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("list users: create request: %w", err)
	}
	c.setAuth(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("list users: do request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("list users: unexpected status %d: %s", resp.StatusCode, string(body))
	}

	var users []User
	if err := json.NewDecoder(resp.Body).Decode(&users); err != nil {
		return nil, fmt.Errorf("list users: decode response: %w", err)
	}
	return users, nil
}

// patchFinding sends a PATCH request to /api/findings/{id}.
func (c *APIClient) patchFinding(ctx context.Context, findingID string, payload findingStatusUpdatePayload) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("patch finding %s: marshal payload: %w", findingID, err)
	}

	u := c.baseURL + "/api/findings/" + findingID
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, u, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("patch finding %s: create request: %w", findingID, err)
	}
	req.Header.Set("Content-Type", "application/json")
	c.setAuth(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("patch finding %s: do request: %w", findingID, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("patch finding %s: unexpected status %d: %s", findingID, resp.StatusCode, string(respBody))
	}
	return nil
}

func (c *APIClient) setAuth(req *http.Request) {
	req.Header.Set("Authorization", "Bearer "+c.apiToken)
}
