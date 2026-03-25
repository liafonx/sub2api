package service

import (
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/stretchr/testify/require"
)

// TestIsModelSupportedByAccount_ProviderRouting verifies that when
// EnforceProviderRouting is enabled, isModelSupportedByAccount rejects
// requests whose model's litellm_provider does not match the account platform.
func TestIsModelSupportedByAccount_ProviderRouting(t *testing.T) {
	makeSvc := func(providers map[string]string, enforce bool) *GatewayService {
		return &GatewayService{
			cfg: &config.Config{
				Pricing: config.PricingConfig{EnforceProviderRouting: enforce},
			},
			pricingService: &PricingService{
				modelProvider: providers,
			},
		}
	}

	t.Run("openai model rejected on anthropic account", func(t *testing.T) {
		svc := makeSvc(map[string]string{"gpt-4o": "openai"}, true)
		account := &Account{Platform: PlatformAnthropic, Type: AccountTypeAPIKey}
		require.False(t, svc.isModelSupportedByAccount(account, "gpt-4o"))
	})

	t.Run("anthropic model accepted on anthropic API-key account", func(t *testing.T) {
		svc := makeSvc(map[string]string{"claude-3-5-sonnet-20241022": "anthropic"}, true)
		account := &Account{
			Platform: PlatformAnthropic,
			Type:     AccountTypeAPIKey,
			Credentials: map[string]any{
				"model_mapping": map[string]any{
					"claude-3-5-sonnet-20241022": "claude-3-5-sonnet-20241022",
				},
			},
		}
		require.True(t, svc.isModelSupportedByAccount(account, "claude-3-5-sonnet-20241022"))
	})

	t.Run("unknown model passes through (fail-open)", func(t *testing.T) {
		svc := makeSvc(map[string]string{}, true) // empty index — no known providers
		account := &Account{
			Platform: PlatformAnthropic,
			Type:     AccountTypeAPIKey,
			Credentials: map[string]any{
				"model_mapping": map[string]any{
					"my-custom-model": "my-custom-model",
				},
			},
		}
		require.True(t, svc.isModelSupportedByAccount(account, "my-custom-model"))
	})

	t.Run("openai model accepted on openai account", func(t *testing.T) {
		svc := makeSvc(map[string]string{"gpt-4o": "openai"}, true)
		account := &Account{
			Platform: PlatformOpenAI,
			Type:     AccountTypeAPIKey,
			Credentials: map[string]any{
				"model_mapping": map[string]any{
					"gpt-4o": "gpt-4o",
				},
			},
		}
		require.True(t, svc.isModelSupportedByAccount(account, "gpt-4o"))
	})

	t.Run("enforce=false allows mismatched model through", func(t *testing.T) {
		svc := makeSvc(map[string]string{"gpt-4o": "openai"}, false)
		account := &Account{
			Platform: PlatformAnthropic,
			Type:     AccountTypeAPIKey,
			Credentials: map[string]any{
				"model_mapping": map[string]any{
					"gpt-4o": "gpt-4o",
				},
			},
		}
		// With enforcement off the provider check is skipped;
		// result depends only on account.IsModelSupported.
		require.True(t, svc.isModelSupportedByAccount(account, "gpt-4o"))
	})
}
