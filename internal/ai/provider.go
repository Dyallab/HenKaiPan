package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"aspm/internal/config"
)

var cfg *config.Config

// Init initializes the AI provider with the application config.
// Must be called at startup.
func Init(c *config.Config) {
	cfg = c
	SetOpenRouterConfig(c.OpenRouterAPIKey, c.OpenRouterModel)
	SetCloudflareConfig(c.CfAccountID, c.CfAPIToken)
	SetOllamaConfig(c.OllamaURL, c.OllamaModel)
}

// GenerateRemediation generates remediation guidance for a security finding.
// Uses the provider and model specified by AI_REMEDIATION_PROVIDER env var.
func GenerateRemediation(ctx context.Context, req RemediationRequest) (string, error) {
	if cfg == nil {
		return "", ErrAIProviderNotConfigured
	}

	if !cfg.RemediationConfig.IsConfigured {
		return "", ErrAIProviderNotConfigured
	}

	return generateWithProvider(
		ctx,
		cfg.RemediationConfig,
		remediationSystemPrompt,
		buildPrompt(req),
		2048,
	)
}

// GenerateSummary generates a summary of a security finding.
// Uses the provider and model specified by AI_SUMMARY_PROVIDER env var.
func GenerateSummary(ctx context.Context, systemPrompt, userPrompt string) (string, error) {
	if cfg == nil {
		return "", ErrAIProviderNotConfigured
	}

	if !cfg.SummaryConfig.IsConfigured {
		return "", ErrAIProviderNotConfigured
	}

	return generateWithProvider(
		ctx,
		cfg.SummaryConfig,
		systemPrompt,
		userPrompt,
		2048,
	)
}

// GenerateValidation generates a validation check for false positive detection.
// Uses the provider and model specified by AI_VALIDATION_PROVIDER env var.
func GenerateValidation(ctx context.Context, systemPrompt, userPrompt string) (string, error) {
	if cfg == nil {
		return "", ErrAIProviderNotConfigured
	}

	if !cfg.ValidationConfig.IsConfigured {
		return "", ErrAIProviderNotConfigured
	}

	return generateWithProvider(
		ctx,
		cfg.ValidationConfig,
		systemPrompt,
		userPrompt,
		2048,
	)
}

// GenerateValidationJSON generates and parses a structured validation response
// using the provider and model specified by AI_VALIDATION_PROVIDER env var.
func GenerateValidationJSON[T any](ctx context.Context, systemPrompt, userPrompt string) (*T, error) {
	content, err := GenerateValidation(ctx, systemPrompt+"\n\nReturn a single JSON object only. Do not use markdown fences.", userPrompt)
	if err != nil {
		return nil, err
	}

	cleaned := strings.TrimSpace(content)
	var target T
	if err := json.Unmarshal([]byte(cleaned), &target); err == nil {
		return &target, nil
	}

	jsonObject, err := extractJSONObject(cleaned)
	if err != nil {
		return nil, fmt.Errorf("parse structured validation response: %w", err)
	}
	if err := json.Unmarshal([]byte(jsonObject), &target); err != nil {
		repaired := repairInvalidJSONEscapes(jsonObject)
		if repairErr := json.Unmarshal([]byte(repaired), &target); repairErr != nil {
			return nil, fmt.Errorf("unmarshal structured validation response: %w", err)
		}
	}
	return &target, nil
}

func repairInvalidJSONEscapes(content string) string {
	var b strings.Builder
	b.Grow(len(content))

	for i := 0; i < len(content); i++ {
		if content[i] != '\\' || i+1 >= len(content) {
			b.WriteByte(content[i])
			continue
		}

		next := content[i+1]
		switch next {
		case '"', '\\', '/', 'b', 'f', 'n', 'r', 't', 'u':
			b.WriteByte(content[i])
		default:
			continue
		}
	}

	return b.String()
}

// GenerateTextWithModel generates text using a specific model identifier.
// If the model starts with @cf/, it uses Cloudflare. If it's "ollama" or starts with ollama/, it uses Ollama. Otherwise, uses OpenRouter.
// This function allows explicit model selection and is useful for dynamic model switching.
func GenerateTextWithModel(ctx context.Context, systemPrompt, userPrompt string, maxTokens int, modelName string) (string, error) {
	if cfg == nil {
		return "", ErrAIProviderNotConfigured
	}

	// Determine provider based on model prefix or config
	var provider *config.ProviderConfig
	if strings.HasPrefix(modelName, "@cf/") {
		provider = &config.ProviderConfig{
			Name:         "cloudflare",
			Model:        modelName,
			IsConfigured: cfg.CfAccountID != "" && cfg.CfAPIToken != "",
		}
	} else if strings.HasPrefix(modelName, "ollama/") || modelName == "ollama" {
		provider = &config.ProviderConfig{
			Name:         "ollama",
			Model:        strings.TrimPrefix(modelName, "ollama/"),
			IsConfigured: cfg.OllamaURL != "",
		}
	} else {
		provider = &config.ProviderConfig{
			Name:         "openrouter",
			Model:        modelName,
			IsConfigured: cfg.OpenRouterAPIKey != "",
		}
	}

	if !provider.IsConfigured {
		return "", ErrAIProviderNotConfigured
	}

	return generateWithProvider(ctx, provider, systemPrompt, userPrompt, maxTokens)
}

// generateWithProvider is the core router that dispatches to the appropriate provider.
func generateWithProvider(ctx context.Context, provider *config.ProviderConfig, systemPrompt, userPrompt string, maxTokens int) (string, error) {
	switch provider.Name {
	case "cloudflare":
		if !CloudflareEnabled() {
			return "", ErrAIProviderNotConfigured
		}
		return CloudflareGenerate(ctx, provider.Model, systemPrompt, userPrompt)

	case "ollama":
		if !OllamaEnabled() {
			return "", ErrAIProviderNotConfigured
		}
		return OllamaGenerate(ctx, provider.Model, systemPrompt, userPrompt)

	case "openrouter":
		if OpenRouterKey() == "" {
			return "", ErrAIProviderNotConfigured
		}
		if maxTokens == 0 {
			maxTokens = 2048
		}
		return OpenRouterGenerateTextWithModel(ctx, systemPrompt, userPrompt, maxTokens, provider.Model)

	default:
		return "", ErrAIProviderNotSupported
	}
}

var (
	ErrAIProviderNotConfigured = &aiError{"AI provider not configured"}
	ErrAIProviderNotSupported  = &aiError{"AI provider not supported"}
)

type aiError struct {
	msg string
}

func (e *aiError) Error() string {
	return e.msg
}
