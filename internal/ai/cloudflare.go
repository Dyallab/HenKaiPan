package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const cfBaseURL = "https://api.cloudflare.com/client/v4/accounts"

var (
	cfAccountID string
	cfAPIToken  string
	cfClient    *http.Client
)

func init() {
	cfClient = &http.Client{
		Timeout: 30 * time.Second,
	}
}

func SetCloudflareConfig(accountID, apiToken string) {
	cfAccountID = strings.TrimSpace(accountID)
	cfAPIToken = strings.TrimSpace(apiToken)
}

func CloudflareEnabled() bool {
	return cfAccountID != "" && cfAPIToken != ""
}

type cfMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type cfRequest struct {
	Messages []cfMessage `json:"messages"`
}

type cfResponse struct {
	Success bool `json:"success"`
	Result  struct {
		Response string `json:"response"`
	} `json:"result"`
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors"`
}

func CloudflareGenerate(ctx context.Context, model, systemPrompt, userPrompt string) (string, error) {
	if !CloudflareEnabled() {
		return "", errors.New("cloudflare not configured")
	}

	reqBody := cfRequest{
		Messages: []cfMessage{
			{Role: "system", Content: systemPrompt},
			{Role: "user", Content: userPrompt},
		},
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("marshal cloudflare request: %w", err)
	}

	url := fmt.Sprintf("%s/%s/ai/run/%s", cfBaseURL, cfAccountID, model)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("create cloudflare request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+cfAPIToken)

	resp, err := cfClient.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("call cloudflare: %w", err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read cloudflare response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("cloudflare API %d: %s", resp.StatusCode, string(raw))
	}

	var result cfResponse
	if err := json.Unmarshal(raw, &result); err != nil {
		return "", fmt.Errorf("decode cloudflare response: %w", err)
	}
	if len(result.Errors) > 0 {
		return "", fmt.Errorf("cloudflare error: %s", result.Errors[0].Message)
	}
	if !result.Success {
		return "", errors.New("cloudflare request failed")
	}

	return strings.TrimSpace(result.Result.Response), nil
}

