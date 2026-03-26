package service

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/ctxkey"
	"github.com/stretchr/testify/require"
)

func TestClaudeCodeValidator_ProbeBypass(t *testing.T) {
	validator := NewClaudeCodeValidator(nil)
	req := httptest.NewRequest(http.MethodPost, "http://example.com/v1/messages", nil)
	req.Header.Set("User-Agent", "claude-cli/1.2.3 (darwin; arm64)")
	req = req.WithContext(context.WithValue(req.Context(), ctxkey.IsMaxTokensOneHaikuRequest, true))

	ok := validator.Validate(req, map[string]any{
		"model":      "claude-haiku-4-5",
		"max_tokens": 1,
	})
	require.True(t, ok)
}

func TestClaudeCodeValidator_ProbeBypassRequiresUA(t *testing.T) {
	validator := NewClaudeCodeValidator(nil)
	req := httptest.NewRequest(http.MethodPost, "http://example.com/v1/messages", nil)
	req.Header.Set("User-Agent", "curl/8.0.0")
	req = req.WithContext(context.WithValue(req.Context(), ctxkey.IsMaxTokensOneHaikuRequest, true))

	ok := validator.Validate(req, map[string]any{
		"model":      "claude-haiku-4-5",
		"max_tokens": 1,
	})
	require.False(t, ok)
}

func TestClaudeCodeValidator_MessagesWithoutProbeStillNeedStrictValidation(t *testing.T) {
	validator := NewClaudeCodeValidator(nil)
	req := httptest.NewRequest(http.MethodPost, "http://example.com/v1/messages", nil)
	req.Header.Set("User-Agent", "claude-cli/1.2.3 (darwin; arm64)")

	ok := validator.Validate(req, map[string]any{
		"model":      "claude-haiku-4-5",
		"max_tokens": 1,
	})
	require.False(t, ok)
}

func TestClaudeCodeValidator_NonMessagesPathUAOnly(t *testing.T) {
	validator := NewClaudeCodeValidator(nil)
	req := httptest.NewRequest(http.MethodPost, "http://example.com/v1/models", nil)
	req.Header.Set("User-Agent", "claude-cli/1.2.3 (darwin; arm64)")

	ok := validator.Validate(req, nil)
	require.True(t, ok)
}

func TestExtractVersion(t *testing.T) {
	v := NewClaudeCodeValidator(nil)
	tests := []struct {
		ua   string
		want string
	}{
		{"claude-cli/2.1.22 (darwin; arm64)", "2.1.22"},
		{"claude-cli/1.0.0", "1.0.0"},
		{"Claude-CLI/3.10.5 (linux; x86_64)", "3.10.5"}, // 大小写不敏感
		{"curl/8.0.0", ""},                              // 非 Claude CLI
		{"", ""},                                        // 空字符串
		{"claude-cli/", ""},                             // 无版本号
		{"claude-cli/2.1.22-beta", "2.1.22"},            // 带后缀仍提取主版本号
	}
	for _, tt := range tests {
		got := v.ExtractVersion(tt.ua)
		require.Equal(t, tt.want, got, "ExtractVersion(%q)", tt.ua)
	}
}

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"2.1.0", "2.1.0", 0},   // 相等
		{"2.1.1", "2.1.0", 1},   // patch 更大
		{"2.0.0", "2.1.0", -1},  // minor 更小
		{"3.0.0", "2.99.99", 1}, // major 更大
		{"1.0.0", "2.0.0", -1},  // major 更小
		{"0.0.1", "0.0.0", 1},   // patch 差异
		{"", "1.0.0", -1},       // 空字符串 vs 正常版本
		{"v2.1.0", "2.1.0", 0},  // v 前缀处理
	}
	for _, tt := range tests {
		got := CompareVersions(tt.a, tt.b)
		require.Equal(t, tt.want, got, "CompareVersions(%q, %q)", tt.a, tt.b)
	}
}

func TestSetGetClaudeCodeVersion(t *testing.T) {
	ctx := context.Background()
	require.Equal(t, "", GetClaudeCodeVersion(ctx), "empty context should return empty string")

	ctx = SetClaudeCodeVersion(ctx, "2.1.63")
	require.Equal(t, "2.1.63", GetClaudeCodeVersion(ctx))
}

// buildValidCCRequest builds a minimal valid CC /v1/messages request.
func buildValidCCRequest(t *testing.T) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "http://example.com/v1/messages", nil)
	req.Header.Set("User-Agent", "claude-cli/2.1.81 (darwin; arm64)")
	req.Header.Set("X-App", "claude-code")
	req.Header.Set("anthropic-beta", "interleaved-thinking-2025-05-14")
	req.Header.Set("anthropic-version", "2023-06-01")
	return req
}

func buildValidCCBody() map[string]any {
	// user_id must match legacy format: user_{64hex}_account_{uuid}_session_{uuid}
	const validUserID = "user_" +
		"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789" +
		"_account_" +
		"_session_" +
		"550e8400-e29b-41d4-a716-446655440000"
	return map[string]any{
		"model": "claude-sonnet-4-6",
		"system": []any{
			map[string]any{
				"type": "text",
				"text": "You are Claude Code, Anthropic's official CLI for Claude.",
			},
		},
		"metadata": map[string]any{
			"user_id": validUserID,
		},
	}
}

// --- Nil registry: identical to original behavior ---

func TestClaudeCodeValidator_NilRegistry_PassesValidRequest(t *testing.T) {
	v := NewClaudeCodeValidator(nil)
	req := buildValidCCRequest(t)
	body := buildValidCCBody()
	require.True(t, v.Validate(req, body))
}

func TestClaudeCodeValidator_NilRegistry_FailsWrongUA(t *testing.T) {
	v := NewClaudeCodeValidator(nil)
	req := buildValidCCRequest(t)
	req.Header.Set("User-Agent", "curl/8.0.0")
	require.False(t, v.Validate(req, buildValidCCBody()))
}

// --- Registry-driven X-App exact match ---

func makeRegistryWithFreshSnap(t *testing.T, snap *CCTraitSnapshot) *CCTraitRegistry {
	t.Helper()
	r := makeRegistry(t, &mockTraitCache{snap: snap})
	r.mu.Lock()
	r.snapshot = snap
	r.mu.Unlock()
	return r
}

func freshSnap() *CCTraitSnapshot {
	flags := []string{"interleaved-thinking-2025-05-14"}
	return &CCTraitSnapshot{
		Version:              "2.1.81",
		XAppValue:            "claude-code",
		BetaFlags:            flags,
		BetaFlagSet:          buildBetaFlagSet(flags),
		SystemPromptPrefixes: claudeCodeSystemPrompts,
		UpdatedAt:            time.Now(),
	}
}

func TestClaudeCodeValidator_Registry_XAppExactMatch_Pass(t *testing.T) {
	v := NewClaudeCodeValidator(makeRegistryWithFreshSnap(t, freshSnap()))
	req := buildValidCCRequest(t)
	require.True(t, v.Validate(req, buildValidCCBody()))
}

func TestClaudeCodeValidator_Registry_XAppExactMatch_Fail(t *testing.T) {
	v := NewClaudeCodeValidator(makeRegistryWithFreshSnap(t, freshSnap()))
	req := buildValidCCRequest(t)
	req.Header.Set("X-App", "other-app")
	require.False(t, v.Validate(req, buildValidCCBody()))
}

// --- Registry-driven beta flag validation ---

func TestClaudeCodeValidator_Registry_BetaFlag_KnownFlag_Pass(t *testing.T) {
	v := NewClaudeCodeValidator(makeRegistryWithFreshSnap(t, freshSnap()))
	req := buildValidCCRequest(t)
	req.Header.Set("anthropic-beta", "interleaved-thinking-2025-05-14,some-other-flag")
	require.True(t, v.Validate(req, buildValidCCBody()))
}

func TestClaudeCodeValidator_Registry_BetaFlag_UnknownFlag_Fail(t *testing.T) {
	v := NewClaudeCodeValidator(makeRegistryWithFreshSnap(t, freshSnap()))
	req := buildValidCCRequest(t)
	req.Header.Set("anthropic-beta", "completely-unknown-flag-xyz")
	require.False(t, v.Validate(req, buildValidCCBody()))
}

// --- Staleness degradation ---

func staleSnap() *CCTraitSnapshot {
	s := freshSnap()
	s.UpdatedAt = time.Now().Add(-8 * 24 * time.Hour) // 8 days old
	return s
}

func TestClaudeCodeValidator_StaleRegistry_XAppNonEmptyOnly(t *testing.T) {
	v := NewClaudeCodeValidator(makeRegistryWithFreshSnap(t, staleSnap()))
	req := buildValidCCRequest(t)
	// Any non-empty X-App passes when snapshot is stale
	req.Header.Set("X-App", "any-value-is-ok")
	require.True(t, v.Validate(req, buildValidCCBody()))
}

func TestClaudeCodeValidator_StaleRegistry_BetaNonEmptyOnly(t *testing.T) {
	v := NewClaudeCodeValidator(makeRegistryWithFreshSnap(t, staleSnap()))
	req := buildValidCCRequest(t)
	req.Header.Set("anthropic-beta", "completely-unknown-flag")
	// Stale snapshot → degrades to non-empty check → passes
	require.True(t, v.Validate(req, buildValidCCBody()))
}

// --- System prompt uses registry prefixes ---

func TestClaudeCodeValidator_Registry_SystemPromptUsesRegistryPrefixes(t *testing.T) {
	snap := freshSnap()
	snap.SystemPromptPrefixes = []string{"You are a custom registry prompt for testing."}
	v := NewClaudeCodeValidator(makeRegistryWithFreshSnap(t, snap))

	req := buildValidCCRequest(t)
	body := buildValidCCBody()
	body["system"] = []any{
		map[string]any{"type": "text", "text": "You are a custom registry prompt for testing. More details here."},
	}
	require.True(t, v.Validate(req, body))
}

func TestClaudeCodeValidator_Registry_SystemPromptFails_WhenNoMatch(t *testing.T) {
	snap := freshSnap()
	snap.SystemPromptPrefixes = []string{"You are a custom registry prompt."}
	v := NewClaudeCodeValidator(makeRegistryWithFreshSnap(t, snap))

	req := buildValidCCRequest(t)
	body := buildValidCCBody()
	body["system"] = []any{
		map[string]any{"type": "text", "text": "I am a completely unrelated system prompt with no similarity."},
	}
	require.False(t, v.Validate(req, body))
}

// --- hasAnyKnownBetaFlag ---

func TestHasAnyKnownBetaFlag(t *testing.T) {
	known := []string{"flag-a", "flag-b"}
	require.True(t, hasAnyKnownBetaFlag("flag-a,flag-c", known))
	require.True(t, hasAnyKnownBetaFlag("flag-b", known))
	require.False(t, hasAnyKnownBetaFlag("flag-x,flag-y", known))
	require.False(t, hasAnyKnownBetaFlag("", known))
}
