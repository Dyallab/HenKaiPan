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

const defaultOllamaURL = "http://localhost:11434"

var (
	ollamaURL    string
	ollamaModel  string
	ollamaClient *http.Client
)

func init() {
	ollamaClient = &http.Client{
		Timeout: 180 * time.Second,
	}
}

func SetOllamaConfig(url, model string) {
	ollamaURL = strings.TrimSpace(url)
	if ollamaURL == "" {
		ollamaURL = defaultOllamaURL
	}
	ollamaModel = strings.TrimSpace(model)
	if ollamaModel == "" {
		ollamaModel = "gemma4:e4b"
	}
}

func OllamaEnabled() bool {
	return ollamaURL != "" && ollamaModel != ""
}

type ollamaMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type ollamaRequest struct {
	Model   string          `json:"model"`
	Messages []ollamaMessage `json:"messages"`
	Stream  bool            `json:"stream"`
	Options ollamaOptions   `json:"options,omitempty"`
}

type ollamaOptions struct {
	Temperature float64 `json:"temperature,omitempty"`
	NumPredict  int     `json:"num_predict,omitempty"`
}

type ollamaResponse struct {
	Model     string `json:"model"`
	CreatedAt string `json:"created_at"`
	Message   struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	} `json:"message"`
	Done bool `json:"done"`
}

func OllamaGenerate(ctx context.Context, model, systemPrompt, userPrompt string) (string, error) {
	if !OllamaEnabled() {
		return "", errors.New("ollama not configured")
	}

	// Use provided model if specified, otherwise use default
	modelToUse := model
	if strings.TrimSpace(model) == "" {
		modelToUse = ollamaModel
	}

	reqBody := ollamaRequest{
		Model: modelToUse,
		Messages: []ollamaMessage{
			{Role: "system", Content: systemPrompt},
			{Role: "user", Content: userPrompt},
		},
		Stream: false,
		Options: ollamaOptions{
			Temperature: 0,
			NumPredict:  2048,
		},
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("marshal ollama request: %w", err)
	}

	url := strings.TrimSuffix(ollamaURL, "/") + "/api/chat"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("create ollama request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := ollamaClient.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("call ollama: %w", err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read ollama response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("ollama API %d: %s", resp.StatusCode, string(raw))
	}

	var result ollamaResponse
	if err := json.Unmarshal(raw, &result); err != nil {
		return "", fmt.Errorf("decode ollama response: %w", err)
	}

	if !result.Done {
		return "", errors.New("ollama response incomplete")
	}

	content := strings.TrimSpace(result.Message.Content)
	if content == "" {
		return "", errors.New("empty response from ollama")
	}

	return content, nil
}
