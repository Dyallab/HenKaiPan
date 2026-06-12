package bot

// User represents a user in the HenKaiPan API response.
type User struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
}

// findingStatusUpdatePayload is the JSON body for PATCH /api/findings/{id}.
type findingStatusUpdatePayload struct {
	Status     string `json:"status,omitempty"`
	AssignedTo string `json:"assigned_to,omitempty"`
}
