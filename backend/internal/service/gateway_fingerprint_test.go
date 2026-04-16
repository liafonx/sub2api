// Package service — tests for Patch 25: Claude Code fingerprint hardening.
// These tests are intentionally untagged so they run under plain `go test ./internal/service/...`.
package service

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/claude"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Minimal SettingRepository stub (inline, no build-tag requirement)
// ---------------------------------------------------------------------------

type fingerprintTestSettingRepo struct {
	data map[string]string
	err  error
}

func newFingerprintTestSettingRepo(kvs ...string) *fingerprintTestSettingRepo {
	r := &fingerprintTestSettingRepo{data: make(map[string]string)}
	for i := 0; i+1 < len(kvs); i += 2 {
		r.data[kvs[i]] = kvs[i+1]
	}
	return r
}

func (r *fingerprintTestSettingRepo) Get(_ context.Context, key string) (*Setting, error) {
	if r.err != nil {
		return nil, r.err
	}
	v := r.data[key]
	return &Setting{Key: key, Value: v}, nil
}
func (r *fingerprintTestSettingRepo) GetValue(_ context.Context, key string) (string, error) {
	if r.err != nil {
		return "", r.err
	}
	return r.data[key], nil
}
func (r *fingerprintTestSettingRepo) Set(_ context.Context, key, value string) error {
	r.data[key] = value
	return nil
}
func (r *fingerprintTestSettingRepo) GetMultiple(_ context.Context, keys []string) (map[string]string, error) {
	if r.err != nil {
		return nil, r.err
	}
	out := make(map[string]string, len(keys))
	for _, k := range keys {
		out[k] = r.data[k]
	}
	return out, nil
}
func (r *fingerprintTestSettingRepo) SetMultiple(_ context.Context, settings map[string]string) error {
	for k, v := range settings {
		r.data[k] = v
	}
	return nil
}
func (r *fingerprintTestSettingRepo) GetAll(_ context.Context) (map[string]string, error) {
	if r.err != nil {
		return nil, r.err
	}
	out := make(map[string]string, len(r.data))
	for k, v := range r.data {
		out[k] = v
	}
	return out, nil
}
func (r *fingerprintTestSettingRepo) Delete(_ context.Context, key string) error {
	delete(r.data, key)
	return nil
}

// resetVersionBoundsCache clears the process-level atomic cache so each test
// starts fresh without stale TTL.
func resetVersionBoundsCache() {
	versionBoundsCache.Store(&cachedVersionBounds{
		expiresAt: time.Now().Add(-time.Minute).UnixNano(), // expired
	})
}

// ---------------------------------------------------------------------------
// GetClaudeCodeUserAgent
// ---------------------------------------------------------------------------

func TestGetClaudeCodeUserAgent(t *testing.T) {
	tests := []struct {
		name       string
		minVersion string
		want       string
	}{
		{
			name:       "empty setting returns compile-time default",
			minVersion: "",
			want:       claude.DefaultHeaders["User-Agent"],
		},
		{
			name:       "set to 2.1.111 returns matching UA",
			minVersion: "2.1.111",
			want:       "claude-cli/2.1.111 (external, cli)",
		},
		{
			name:       "set to 2.1.120 returns matching UA",
			minVersion: "2.1.120",
			want:       "claude-cli/2.1.120 (external, cli)",
		},
		{
			name:       "set to 2.0.50 returns matching UA (old version)",
			minVersion: "2.0.50",
			want:       "claude-cli/2.0.50 (external, cli)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetVersionBoundsCache()
			repo := newFingerprintTestSettingRepo(
				SettingKeyMinClaudeCodeVersion, tt.minVersion,
			)
			svc := NewSettingService(repo, nil)
			got := svc.GetClaudeCodeUserAgent(context.Background())
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestGetClaudeCodeUserAgent_DBError(t *testing.T) {
	resetVersionBoundsCache()
	repo := &fingerprintTestSettingRepo{data: make(map[string]string), err: errors.New("db down")}
	svc := NewSettingService(repo, nil)
	// On DB error, should fall back to compile-time default (fail-open).
	got := svc.GetClaudeCodeUserAgent(context.Background())
	assert.Equal(t, claude.DefaultHeaders["User-Agent"], got)
}

// ---------------------------------------------------------------------------
// resolveClaudeCodeUserAgent (GatewayService nil-safety)
// ---------------------------------------------------------------------------

func TestResolveClaudeCodeUserAgent_NilSettingService(t *testing.T) {
	svc := &GatewayService{} // no settingService
	got := svc.resolveClaudeCodeUserAgent(context.Background())
	assert.Equal(t, claude.DefaultHeaders["User-Agent"], got)
}

func TestResolveClaudeCodeUserAgent_NilGatewayService(t *testing.T) {
	var svc *GatewayService
	// Should not panic even on nil receiver.
	got := svc.resolveClaudeCodeUserAgent(context.Background())
	assert.Equal(t, claude.DefaultHeaders["User-Agent"], got)
}

func TestResolveClaudeCodeUserAgent_WithSetting(t *testing.T) {
	resetVersionBoundsCache()
	repo := newFingerprintTestSettingRepo(
		SettingKeyMinClaudeCodeVersion, "2.1.111",
	)
	svc := &GatewayService{
		settingService: NewSettingService(repo, nil),
	}
	got := svc.resolveClaudeCodeUserAgent(context.Background())
	assert.Equal(t, "claude-cli/2.1.111 (external, cli)", got)
}

// ---------------------------------------------------------------------------
// applyClaudeCodeMimicHeaders — UA substitution
// ---------------------------------------------------------------------------

func TestApplyClaudeCodeMimicHeaders_UASubstitution(t *testing.T) {
	req, err := http.NewRequest("POST", "https://api.anthropic.com/v1/messages", nil)
	require.NoError(t, err)

	ua := "claude-cli/2.1.120 (external, cli)"
	applyClaudeCodeMimicHeaders(req, false, ua)

	got := getHeaderRaw(req.Header, "user-agent")
	assert.Equal(t, ua, got, "user-agent should be overridden to the resolved UA")
}

func TestApplyClaudeCodeMimicHeaders_DefaultFallback(t *testing.T) {
	req, err := http.NewRequest("POST", "https://api.anthropic.com/v1/messages", nil)
	require.NoError(t, err)

	compiledUA := claude.DefaultHeaders["User-Agent"]
	applyClaudeCodeMimicHeaders(req, false, compiledUA)

	got := getHeaderRaw(req.Header, "user-agent")
	assert.Equal(t, compiledUA, got)
}

func TestApplyClaudeCodeMimicHeaders_StreamHelper(t *testing.T) {
	req, err := http.NewRequest("POST", "https://api.anthropic.com/v1/messages", nil)
	require.NoError(t, err)

	applyClaudeCodeMimicHeaders(req, true, claude.DefaultHeaders["User-Agent"])

	assert.Equal(t, "stream", getHeaderRaw(req.Header, "x-stainless-helper-method"))
}

// ---------------------------------------------------------------------------
// applyClaudeOAuthHeaderDefaults — fill-missing with UA override
// ---------------------------------------------------------------------------

func TestApplyClaudeOAuthHeaderDefaults_FillsMissing(t *testing.T) {
	req, err := http.NewRequest("POST", "https://api.anthropic.com/v1/messages", nil)
	require.NoError(t, err)

	ua := "claude-cli/2.1.100 (external, cli)"
	applyClaudeOAuthHeaderDefaults(req, ua)

	// Should have filled in the User-Agent with the resolved value.
	assert.Equal(t, ua, getHeaderRaw(req.Header, "user-agent"))
	// Accept should also be set.
	assert.Equal(t, "application/json", getHeaderRaw(req.Header, "Accept"))
}

func TestApplyClaudeOAuthHeaderDefaults_DoesNotOverwriteExisting(t *testing.T) {
	req, err := http.NewRequest("POST", "https://api.anthropic.com/v1/messages", nil)
	require.NoError(t, err)

	// Pre-set UA as if it came from a real CC client's sticky fingerprint.
	setHeaderRaw(req.Header, "user-agent", "claude-cli/2.2.0 (external, cli)")
	applyClaudeOAuthHeaderDefaults(req, "claude-cli/2.1.111 (external, cli)")

	// fill-missing should NOT overwrite existing header.
	assert.Equal(t, "claude-cli/2.2.0 (external, cli)", getHeaderRaw(req.Header, "user-agent"))
}

// ---------------------------------------------------------------------------
// x-client-request-id auto-generation
// ---------------------------------------------------------------------------

func TestApplyClaudeCodeMimicHeaders_RequestIDIsLowercase(t *testing.T) {
	// Verify that x-client-request-id uses lowercase wire casing (not X-Client-Request-Id).
	req, err := http.NewRequest("POST", "https://api.anthropic.com/v1/messages", nil)
	require.NoError(t, err)

	// Simulate what buildUpstreamRequest does after applyClaudeCodeMimicHeaders.
	applyClaudeCodeMimicHeaders(req, false, claude.DefaultHeaders["User-Agent"])
	if getHeaderRaw(req.Header, "x-client-request-id") == "" {
		setHeaderRaw(req.Header, "x-client-request-id", "test-id-12345")
	}

	// Raw (lowercase) key must be present, not the canonicalized form.
	rawVal := getHeaderRaw(req.Header, "x-client-request-id")
	assert.Equal(t, "test-id-12345", rawVal, "x-client-request-id must use lowercase wire key")
}

// ---------------------------------------------------------------------------
// DefaultHeaders & fallback bumps (compile-time values)
// ---------------------------------------------------------------------------

func TestDefaultHeaders_GroundTruthValues(t *testing.T) {
	assert.Equal(t, "claude-cli/2.1.111 (external, cli)", claude.DefaultHeaders["User-Agent"])
	assert.Equal(t, "0.81.0", claude.DefaultHeaders["X-Stainless-Package-Version"])
	assert.Equal(t, "MacOS", claude.DefaultHeaders["X-Stainless-OS"])
	assert.Equal(t, "v24.3.0", claude.DefaultHeaders["X-Stainless-Runtime-Version"])
	assert.Equal(t, "900", claude.DefaultHeaders["X-Stainless-Timeout"])
}

func TestDefaultFingerprint_GroundTruthValues(t *testing.T) {
	assert.Equal(t, "claude-cli/2.1.111 (external, cli)", defaultFingerprint.UserAgent)
	assert.Equal(t, "0.81.0", defaultFingerprint.StainlessPackageVersion)
	assert.Equal(t, "MacOS", defaultFingerprint.StainlessOS)
	assert.Equal(t, "v24.3.0", defaultFingerprint.StainlessRuntimeVersion)
}

// ---------------------------------------------------------------------------
// Beta constants — 7-beta baseline
// ---------------------------------------------------------------------------

func TestOAuthDefaultBetaBaseline(t *testing.T) {
	// DefaultBetaHeader must match the 7 betas observed in the captured request.
	expected := []string{
		claude.BetaClaudeCode,
		claude.BetaOAuth,
		claude.BetaContext1M,
		claude.BetaInterleavedThinking,
		claude.BetaContextManagement,
		claude.BetaPromptCachingScope,
		claude.BetaEffort,
	}
	got := strings.Split(claude.DefaultBetaHeader, ",")
	assert.Equal(t, expected, got)
}

func TestFineGrainedToolStreamingRemoved(t *testing.T) {
	// fine-grained-tool-streaming must NOT appear in any default header string
	// (it is GA on Claude 4.x and absent from real CC traffic).
	for _, h := range []string{
		claude.DefaultBetaHeader,
		claude.MessageBetaHeaderNoTools,
		claude.MessageBetaHeaderWithTools,
		claude.CountTokensBetaHeader,
		claude.APIKeyBetaHeader,
		claude.HaikuBetaHeader,
	} {
		assert.NotContains(t, h, "fine-grained-tool-streaming",
			"fine-grained-tool-streaming should not appear in default beta headers")
	}
}

// ---------------------------------------------------------------------------
// IsNewMetadataFormatVersion — 2.1.111 is JSON format
// ---------------------------------------------------------------------------

func TestIsNewMetadataFormatVersion_2_1_111(t *testing.T) {
	assert.True(t, IsNewMetadataFormatVersion("2.1.111"),
		"2.1.111 is above the 2.1.78 threshold; should use JSON format")
}

func TestIsNewMetadataFormatVersion_2_0_50(t *testing.T) {
	assert.False(t, IsNewMetadataFormatVersion("2.0.50"),
		"2.0.50 is below the 2.1.78 threshold; should use legacy format")
}
