package service

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIsProviderAllowedForPlatform(t *testing.T) {
	tests := []struct {
		name     string
		provider string
		platform string
		want     bool
	}{
		// Anthropic platform
		{"anthropic provider → anthropic platform", "anthropic", PlatformAnthropic, true},
		{"openai provider → anthropic platform", "openai", PlatformAnthropic, false},
		{"gemini provider → anthropic platform", "gemini", PlatformAnthropic, false},
		{"vertex_ai-language-models → anthropic platform", "vertex_ai-language-models", PlatformAnthropic, false},

		// OpenAI platform
		{"openai provider → openai platform", "openai", PlatformOpenAI, true},
		{"text-completion-openai → openai platform", "text-completion-openai", PlatformOpenAI, true},
		{"anthropic provider → openai platform", "anthropic", PlatformOpenAI, false},

		// Gemini platform
		{"gemini provider → gemini platform", "gemini", PlatformGemini, true},
		{"vertex_ai-language-models → gemini platform", "vertex_ai-language-models", PlatformGemini, true},
		{"vertex_ai-vision-models → gemini platform", "vertex_ai-vision-models", PlatformGemini, true},
		{"vertex_ai-embedding-models → gemini platform", "vertex_ai-embedding-models", PlatformGemini, true},
		{"openai provider → gemini platform", "openai", PlatformGemini, false},

		// Unknown provider → fail open (returns true)
		{"unknown provider → any platform", "some-unknown-provider", PlatformAnthropic, true},
		{"empty provider → anthropic platform", "", PlatformAnthropic, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isProviderAllowedForPlatform(tt.provider, tt.platform)
			require.Equal(t, tt.want, got)
		})
	}
}
