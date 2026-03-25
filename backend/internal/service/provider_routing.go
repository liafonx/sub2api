package service

// platformToProviders maps platform constants to accepted litellm_provider values.
var platformToProviders = map[string][]string{
	PlatformAnthropic: {"anthropic"},
	PlatformOpenAI:    {"openai", "text-completion-openai"},
	PlatformGemini:    {"gemini", "vertex_ai-language-models", "vertex_ai-vision-models", "vertex_ai-embedding-models"},
}

// providerToPlatform is the reverse index: litellm_provider → platform.
// Built once at init time for O(1) lookup.
var providerToPlatform = make(map[string]string)

func init() {
	for platform, providers := range platformToProviders {
		for _, p := range providers {
			providerToPlatform[p] = platform
		}
	}
}

// isProviderAllowedForPlatform returns true if the given litellm_provider is
// accepted by the given platform. Unknown providers (not in the mapping) pass
// through (fail-open) — the caller is responsible for the fail-open policy.
func isProviderAllowedForPlatform(provider, platform string) bool {
	mapped, ok := providerToPlatform[provider]
	if !ok {
		// Unknown provider → fail open (caller decides)
		return true
	}
	return mapped == platform
}
