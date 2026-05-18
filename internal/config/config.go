package config

import (
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
)

// ProviderConfig represents the configuration for a specific AI provider task (remediation, summary, validation)
type ProviderConfig struct {
	// Name is the provider name: "cloudflare", "openrouter", or "ollama"
	Name string
	// Model is the model identifier (e.g. "@cf/meta/llama-3.1-8b-instruct", "openai/gpt-4.1-mini", or "gemma4:e4b")
	Model string
	// IsConfigured returns true if both provider name and credentials are available
	IsConfigured bool
}

type Config struct {
	DatabaseURL          string // required
	JWTSecret            string // required
	SecretEncryptionKey  string // required for encrypting sensitive DB fields
	RedisAddr            string // default: localhost:6379
	Port                 string // default: 8080
	FrontendURL          string // optional: public frontend URL for external backlinks
	CookieSecure         bool   // default: false; set true behind HTTPS
	CookieDomain         string // optional: cookie domain for production (e.g. ".example.com")
	CookieSameSite       string // optional: "lax" (default), "strict", or "none" (requires Secure=true)
	LicenseKey           string // optional: license key for self-hosted features
	WebhookSecret        string // optional: secret for HMAC webhook signature validation

	SMTPHost     string // optional email notifications
	SMTPPort     string // default: 587
	SMTPUsername string
	SMTPPassword string
	SMTPFrom     string
	EmailEnabled bool

	// OpenRouter configuration (optional)
	OpenRouterAPIKey string
	OpenRouterModel  string

	// Cloudflare Workers AI configuration (optional)
	CfAccountID string
	CfAPIToken  string
	CfModel     string
	CfModelSumm string

	// Ollama configuration (optional, for self-hosted free tier)
	OllamaURL   string
	OllamaModel string

	// AI Provider selection per task (remediation, summary, validation)
	AIRemediationProvider string
	AISummaryProvider     string
	AIValidationProvider  string

	// Task-specific provider configs (resolved at startup)
	RemediationConfig *ProviderConfig
	SummaryConfig     *ProviderConfig
	ValidationConfig  *ProviderConfig

	// CORS configuration
	AllowedOrigins []string // default: localhost origins
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

	allowedOrigins := []string{"http://localhost:4321", "http://localhost:4322", "http://localhost:3000"}
	if origins := os.Getenv("CORS_ALLOWED_ORIGINS"); origins != "" {
		allowedOrigins = strings.Split(origins, ",")
	}

	cfg := &Config{
		DatabaseURL:           get("DATABASE_URL"),
		JWTSecret:             get("JWT_SECRET"),
		SecretEncryptionKey:   get("SECRET_ENCRYPTION_KEY"),
		RedisAddr:             get("REDIS_ADDR"),
		Port:                  envOr("PORT", "8080"),
		FrontendURL:           os.Getenv("FRONTEND_BASE_URL"),
		CookieSecure:          envBool("COOKIE_SECURE", false),
		CookieDomain:          os.Getenv("COOKIE_DOMAIN"),
		CookieSameSite:        envOr("COOKIE_SAMESITE", "lax"),
		LicenseKey:            os.Getenv("LICENSE_KEY"),
		WebhookSecret:         os.Getenv("WEBHOOK_SECRET"),
		SMTPHost:              os.Getenv("SMTP_HOST"),
		SMTPPort:              envOr("SMTP_PORT", "587"),
		SMTPUsername:          os.Getenv("SMTP_USERNAME"),
		SMTPPassword:          os.Getenv("SMTP_PASSWORD"),
		SMTPFrom:              os.Getenv("EMAIL_FROM"),
		OpenRouterAPIKey:      os.Getenv("OPENROUTER_API_KEY"),
		OpenRouterModel:       envOr("OPENROUTER_MODEL", "openai/gpt-4.1-mini"),
		CfAccountID:           os.Getenv("CF_ACCOUNT_ID"),
		CfAPIToken:            os.Getenv("CF_API_TOKEN"),
		CfModel:               envOr("CF_MODEL", "@cf/meta/llama-3.1-8b-instruct"),
		CfModelSumm:           envOr("CF_MODEL_SUMM", "@cf/google/gemma-3-12b-it"),
		OllamaURL:             envOr("OLLAMA_URL", "http://host.docker.internal:11434"),
		OllamaModel:           envOr("OLLAMA_MODEL", "gemma4:e4b"),
		AIRemediationProvider: envOr("AI_REMEDIATION_PROVIDER", "openrouter"),
		AISummaryProvider:     envOr("AI_SUMMARY_PROVIDER", "ollama"),
		AIValidationProvider:  envOr("AI_VALIDATION_PROVIDER", "openrouter"),
		AllowedOrigins:        allowedOrigins,
	}
	cfg.EmailEnabled = cfg.SMTPHost != "" && cfg.SMTPFrom != ""

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
		"frontend_url_configured", cfg.FrontendURL != "",
		"license_key_configured", cfg.LicenseKey != "",
		"webhook_secret_configured", cfg.WebhookSecret != "",
		"email_notifications_enabled", cfg.EmailEnabled,
		"ai_enabled", cfg.OpenRouterAPIKey != "" || cfg.CfAPIToken != "" || cfg.OllamaURL != "",
		"ai_providers", fmt.Sprintf("openrouter=%t, cloudflare=%t, ollama=%t", cfg.OpenRouterAPIKey != "", cfg.CfAPIToken != "", cfg.OllamaURL != ""),
		"remediation_provider", cfg.RemediationConfig.Name,
		"remediation_model", cfg.RemediationConfig.Model,
		"summary_provider", cfg.SummaryConfig.Name,
		"summary_model", cfg.SummaryConfig.Model,
		"validation_provider", cfg.ValidationConfig.Name,
		"validation_model", cfg.ValidationConfig.Model,
		"cors_allowed_origins", cfg.AllowedOrigins,
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
	case "ollama":
		return &ProviderConfig{
			Name:         "ollama",
			Model:        c.OllamaModel,
			IsConfigured: c.OllamaURL != "",
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

func envBool(key string, def bool) bool {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return def
	}
	v, err := strconv.ParseBool(raw)
	if err != nil {
		slog.Warn("invalid boolean env var, using default", "key", key)
		return def
	}
	return v
}
