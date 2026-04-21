package config

import (
	"log/slog"
	"os"
)

type Config struct {
	DatabaseURL     string // required
	JWTSecret       string // required
	RedisAddr       string // default: localhost:6379
	Port            string // default: 8080
	AnthropicAPIKey string // optional — AI features disabled if empty
}

// Load reads env vars, fatals on missing required vars, returns typed config.
// Call after logger.Init() so errors are structured.
func Load() *Config {
	var errs []string

	get := func(key string) string {
		v := os.Getenv(key)
		if v == "" {
			errs = append(errs, key)
		}
		return v
	}

	cfg := &Config{
		DatabaseURL:     get("DATABASE_URL"),
		JWTSecret:       get("JWT_SECRET"),
		RedisAddr:       envOr("REDIS_ADDR", "localhost:6379"),
		Port:            envOr("PORT", "8080"),
		AnthropicAPIKey: os.Getenv("ANTHROPIC_API_KEY"),
	}

	if len(errs) > 0 {
		for _, k := range errs {
			slog.Error("required env var not set", "key", k)
		}
		os.Exit(1)
	}

	slog.Info("config loaded",
		"redis_addr", cfg.RedisAddr,
		"port", cfg.Port,
		"ai_enabled", cfg.AnthropicAPIKey != "",
	)

	return cfg
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
