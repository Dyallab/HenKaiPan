package config

import (
	"testing"

	"aspm/internal/assert"
)

func TestEnvOr(t *testing.T) {
	t.Run("returns value when set", func(t *testing.T) {
		t.Setenv("TEST_ENV_OR_VAL", "custom-value")
		got := envOr("TEST_ENV_OR_VAL", "default")
		assert.Equal(t, got, "custom-value")
	})

	t.Run("returns default when not set", func(t *testing.T) {
		got := envOr("TEST_ENV_OR_NONEXISTENT", "fallback")
		assert.Equal(t, got, "fallback")
	})

	t.Run("returns default when empty", func(t *testing.T) {
		t.Setenv("TEST_ENV_OR_EMPTY", "")
		got := envOr("TEST_ENV_OR_EMPTY", "default-for-empty")
		assert.Equal(t, got, "default-for-empty")
	})
}

func TestEnvBool(t *testing.T) {
	tests := []struct {
		name  string
		value string
		def   bool
		want  bool
	}{
		{"true literal", "true", false, true},
		{"false literal", "false", true, false},
		{"1 as true", "1", false, true},
		{"0 as false", "0", true, false},
		{"TRUE uppercase", "TRUE", false, true},
		{"invalid uses default", "yes", true, true},
		{"invalid uses default false", "yes", false, false},
		{"empty uses default", "", true, true},
		{"empty uses default false", "", false, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.value != "" {
				t.Setenv("TEST_ENV_BOOL", tc.value)
			}
			got := envBool("TEST_ENV_BOOL", tc.def)
			assert.Equal(t, got, tc.want)
		})
	}
}

func TestResolveProviderConfig_Cloudflare(t *testing.T) {
	cfg := &Config{
		CfAccountID: "acct_123",
		CfAPIToken:  "cf_token_abc",
		CfModel:     "@cf/meta/llama-3.1-8b-instruct",
	}
	pc := cfg.resolveProviderConfig("cloudflare", cfg.CfModel)
	assert.Equal(t, pc.Name, "cloudflare")
	assert.Equal(t, pc.Model, "@cf/meta/llama-3.1-8b-instruct")
	assert.True(t, pc.IsConfigured)
}

func TestResolveProviderConfig_CloudflareNotConfigured(t *testing.T) {
	cfg := &Config{}
	pc := cfg.resolveProviderConfig("cloudflare", "@cf/default-model")
	assert.Equal(t, pc.Name, "cloudflare")
	assert.False(t, pc.IsConfigured)
}

func TestResolveProviderConfig_Ollama(t *testing.T) {
	cfg := &Config{
		OllamaURL:   "http://ollama:11434",
		OllamaModel: "gemma4:e4b",
	}
	pc := cfg.resolveProviderConfig("ollama", "")
	assert.Equal(t, pc.Name, "ollama")
	assert.Equal(t, pc.Model, "gemma4:e4b")
	assert.True(t, pc.IsConfigured)
}

func TestResolveProviderConfig_OllamaNotConfigured(t *testing.T) {
	cfg := &Config{}
	pc := cfg.resolveProviderConfig("ollama", "")
	assert.Equal(t, pc.Name, "ollama")
	assert.False(t, pc.IsConfigured)
}

func TestResolveProviderConfig_OpenRouter(t *testing.T) {
	cfg := &Config{
		OpenRouterAPIKey: "sk-or-v1-xxx",
		OpenRouterModel:  "openai/gpt-4.1-mini",
	}
	pc := cfg.resolveProviderConfig("openrouter", "")
	assert.Equal(t, pc.Name, "openrouter")
	assert.Equal(t, pc.Model, "openai/gpt-4.1-mini")
	assert.True(t, pc.IsConfigured)
}

func TestResolveProviderConfig_EmptyProvider(t *testing.T) {
	cfg := &Config{
		OpenRouterAPIKey: "sk-or-v1-xxx",
		OpenRouterModel:  "openai/gpt-4.1-mini",
	}
	pc := cfg.resolveProviderConfig("", "") // empty defaults to openrouter
	assert.Equal(t, pc.Name, "openrouter")
	assert.Equal(t, pc.Model, "openai/gpt-4.1-mini")
	assert.True(t, pc.IsConfigured)
}

func TestResolveProviderConfig_UnknownProviderDefaults(t *testing.T) {
	cfg := &Config{
		OpenRouterAPIKey: "sk-or-v1-xxx",
		OpenRouterModel:  "openai/gpt-4.1-mini",
	}
	pc := cfg.resolveProviderConfig("nonexistent-provider", "")
	assert.Equal(t, pc.Name, "openrouter")
	assert.Equal(t, pc.Model, "openai/gpt-4.1-mini")
	assert.True(t, pc.IsConfigured)
}
