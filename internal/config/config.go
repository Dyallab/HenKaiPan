package config

import (
	"fmt"
	"log/slog"
	"os"
)

// ProviderConfig represents the configuration for a specific AI provider task (remediation, summary, validation)
type ProviderConfig struct {
	// Name is the provider name: "cloudflare" or "openrouter"
	Name string
	// Model is the model identifier (e.g. "@cf/meta/llama-3.1-8b-instruct" or "openai/gpt-4.1-mini")
	Model string
	// IsConfigured returns true if both provider name and credentials are available
	IsConfigured bool
}

type Config struct {
	DatabaseURL string // required
	JWTSecret   string // required
	RedisAddr   string // default: localhost:6379
	Port        string // default: 8080

	// OpenRouter configuration (optional)
	OpenRouterAPIKey string
	OpenRouterModel  string

	// Cloudflare Workers AI configuration (optional)
	CfAccountID string
	CfAPIToken  string
	CfModel     string
	CfModelSumm string

	// AI Provider selection per task (remediation, summary, validation)
	AIRemediationProvider string
	AISummaryProvider     string
	AIValidationProvider  string

	// Task-specific provider configs (resolved at startup)
	RemediationConfig *ProviderConfig
	SummaryConfig     *ProviderConfig
	ValidationConfig  *ProviderConfig
}

// Load reads env vars, validates required fields, and resolves provider configs.
// Call after logger.Init() so errors are structured.
func Load() *Config {
	var missing []string

	get := func(key string) string {
		v := os.Getenv(key)
		if v == "" {
			missing = append(missing, key)
		}
		return v
	}

	cfg := &Config{
		DatabaseURL:           get("DATABASE_URL"),
		JWTSecret:             get("JWT_SECRET"),
		RedisAddr:             envOr("REDIS_ADDR", "localhost:6379"),
		Port:                  envOr("PORT", "8080"),
		OpenRouterAPIKey:      os.Getenv("OPENROUTER_API_KEY"),
		OpenRouterModel:       envOr("OPENROUTER_MODEL", "openai/gpt-4.1-mini"),
		CfAccountID:           os.Getenv("CF_ACCOUNT_ID"),
		CfAPIToken:            os.Getenv("CF_API_TOKEN"),
		CfModel:               envOr("CF_MODEL", "@cf/meta/llama-3.1-8b-instruct"),
		CfModelSumm:           envOr("CF_MODEL_SUMM", "@cf/google/gemma-3-12b-it"),
		AIRemediationProvider: envOr("AI_REMEDIATION_PROVIDER", "openrouter"),
		AISummaryProvider:     envOr("AI_SUMMARY_PROVIDER", "openrouter"),
		AIValidationProvider:  envOr("AI_VALIDATION_PROVIDER", "openrouter"),
	}

	if len(missing) > 0 {
		for _, k := range missing {
			slog.Error("required env var not set", "key", k)
		}
		os.Exit(1)
	}

	// Resolve provider configs based on provider selection
	cfg.RemediationConfig = cfg.resolveProviderConfig(cfg.AIRemediationProvider, cfg.CfModel)
	cfg.SummaryConfig = cfg.resolveProviderConfig(cfg.AISummaryProvider, cfg.CfModelSumm)
	cfg.ValidationConfig = cfg.resolveProviderConfig(cfg.AIValidationProvider, cfg.CfModelSumm)

	slog.Info("config loaded",
		"redis_addr", cfg.RedisAddr,
		"port", cfg.Port,
		"ai_enabled", cfg.OpenRouterAPIKey != "" || cfg.CfAPIToken != "",
		"ai_providers", fmt.Sprintf("openrouter=%t, cloudflare=%t", cfg.OpenRouterAPIKey != "", cfg.CfAPIToken != ""),
		"remediation_provider", cfg.RemediationConfig.Name,
		"remediation_model", cfg.RemediationConfig.Model,
		"summary_provider", cfg.SummaryConfig.Name,
		"summary_model", cfg.SummaryConfig.Model,
		"validation_provider", cfg.ValidationConfig.Name,
		"validation_model", cfg.ValidationConfig.Model,
	)

	return cfg
}

// resolveProviderConfig determines the provider and model for a given task.
// cloudflareModel is used as fallback model for cloudflare provider.
func (c *Config) resolveProviderConfig(provider string, cloudflareModel string) *ProviderConfig {
	switch provider {
	case "cloudflare":
		return &ProviderConfig{
			Name:         "cloudflare",
			Model:        cloudflareModel,
			IsConfigured: c.CfAccountID != "" && c.CfAPIToken != "",
		}
	case "openrouter", "":
		return &ProviderConfig{
			Name:         "openrouter",
			Model:        c.OpenRouterModel,
			IsConfigured: c.OpenRouterAPIKey != "",
		}
	default:
		// Unknown provider, default to openrouter
		slog.Warn("unknown AI provider, defaulting to openrouter", "provider", provider)
		return &ProviderConfig{
			Name:         "openrouter",
			Model:        c.OpenRouterModel,
			IsConfigured: c.OpenRouterAPIKey != "",
		}
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
