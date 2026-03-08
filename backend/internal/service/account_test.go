package service

import (
	"testing"
	"time"
)

func TestIsUserQuotaEnabled(t *testing.T) {
	tests := []struct {
		name    string
		account *Account
		want    bool
	}{
		{
			name: "anthropic_oauth_enabled",
			account: &Account{
				Platform: PlatformAnthropic,
				Type:     AccountTypeOAuth,
				Extra:    map[string]any{"user_quota_enabled": true},
			},
			want: true,
		},
		{
			name: "anthropic_setup_token_enabled",
			account: &Account{
				Platform: PlatformAnthropic,
				Type:     AccountTypeSetupToken,
				Extra:    map[string]any{"user_quota_enabled": true},
			},
			want: true,
		},
		{
			name: "not_anthropic",
			account: &Account{
				Platform: PlatformOpenAI,
				Type:     AccountTypeOAuth,
				Extra:    map[string]any{"user_quota_enabled": true},
			},
			want: false,
		},
		{
			name: "nil_extra",
			account: &Account{
				Platform: PlatformAnthropic,
				Type:     AccountTypeOAuth,
				Extra:    nil,
			},
			want: false,
		},
		{
			name: "missing_key",
			account: &Account{
				Platform: PlatformAnthropic,
				Type:     AccountTypeOAuth,
				Extra:    map[string]any{},
			},
			want: false,
		},
		{
			name: "false_value",
			account: &Account{
				Platform: PlatformAnthropic,
				Type:     AccountTypeOAuth,
				Extra:    map[string]any{"user_quota_enabled": false},
			},
			want: false,
		},
		{
			name: "non_bool_value",
			account: &Account{
				Platform: PlatformAnthropic,
				Type:     AccountTypeOAuth,
				Extra:    map[string]any{"user_quota_enabled": 1},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.account.IsUserQuotaEnabled(); got != tt.want {
				t.Errorf("IsUserQuotaEnabled() = %t, want %t", got, tt.want)
			}
		})
	}
}

func TestGetUserQuotaIdleTimeout(t *testing.T) {
	tests := []struct {
		name    string
		account *Account
		want    time.Duration
	}{
		{
			name: "nil_extra",
			account: &Account{
				Platform: PlatformAnthropic,
				Type:     AccountTypeOAuth,
				Extra:    nil,
			},
			want: 60 * time.Second,
		},
		{
			name: "no_key",
			account: &Account{
				Platform: PlatformAnthropic,
				Type:     AccountTypeOAuth,
				Extra:    map[string]any{},
			},
			want: 60 * time.Second,
		},
		{
			name: "custom_120s",
			account: &Account{
				Platform: PlatformAnthropic,
				Type:     AccountTypeOAuth,
				Extra:    map[string]any{"user_quota_idle_timeout": 120},
			},
			want: 120 * time.Second,
		},
		{
			name: "invalid_negative",
			account: &Account{
				Platform: PlatformAnthropic,
				Type:     AccountTypeOAuth,
				Extra:    map[string]any{"user_quota_idle_timeout": -5},
			},
			want: 60 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.account.GetUserQuotaIdleTimeout(); got != tt.want {
				t.Errorf("GetUserQuotaIdleTimeout() = %s, want %s", got, tt.want)
			}
		})
	}
}
