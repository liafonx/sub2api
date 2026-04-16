// Package service — tests for Patch 25: Claude Code fingerprint hardening.
// These tests are intentionally untagged so they run under plain `go test ./internal/service/...`.
package service

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/claude"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
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

// ---------------------------------------------------------------------------
// Patch 26 — Same-Device, Per-User-Session Identity
// ---------------------------------------------------------------------------

// fakeIdentityCache is an in-memory IdentityCache used across Patch 26 tests.
// setUserCallCount lets TTL-refresh tests assert that each request re-writes
// the cache entry (so the rolling idle timer resets).
type fakeIdentityCache struct {
	fingerprint     map[int64]*Fingerprint
	maskedSessionID map[int64]string
	userSessions    map[string]string // key: "accountID:userID"
	setUserCalls    map[string]int    // key: "accountID:userID"
}

func newFakeIdentityCache() *fakeIdentityCache {
	return &fakeIdentityCache{
		fingerprint:     map[int64]*Fingerprint{},
		maskedSessionID: map[int64]string{},
		userSessions:    map[string]string{},
		setUserCalls:    map[string]int{},
	}
}

func (f *fakeIdentityCache) GetFingerprint(_ context.Context, accountID int64) (*Fingerprint, error) {
	return f.fingerprint[accountID], nil
}
func (f *fakeIdentityCache) SetFingerprint(_ context.Context, accountID int64, fp *Fingerprint) error {
	f.fingerprint[accountID] = fp
	return nil
}
func (f *fakeIdentityCache) GetMaskedSessionID(_ context.Context, accountID int64) (string, error) {
	return f.maskedSessionID[accountID], nil
}
func (f *fakeIdentityCache) SetMaskedSessionID(_ context.Context, accountID int64, sessionID string) error {
	f.maskedSessionID[accountID] = sessionID
	return nil
}
func (f *fakeIdentityCache) GetUserSessionID(_ context.Context, accountID, userID int64) (string, error) {
	return f.userSessions[fakeUserKey(accountID, userID)], nil
}
func (f *fakeIdentityCache) SetUserSessionID(_ context.Context, accountID, userID int64, sessionID string, _ time.Duration) error {
	k := fakeUserKey(accountID, userID)
	f.userSessions[k] = sessionID
	f.setUserCalls[k]++
	return nil
}

func fakeUserKey(accountID, userID int64) string {
	return fmt.Sprintf("%d:%d", accountID, userID)
}

// buildMetadataBody builds a minimal request body with a metadata.user_id
// in the 2.1.111+ JSON format so RewriteUserID round-trips through the same
// path the real gateway uses.
func buildMetadataBody(t *testing.T, deviceID, accountUUID, sessionID, cliVersion string) []byte {
	t.Helper()
	uid := FormatMetadataUserID(deviceID, accountUUID, sessionID, cliVersion)
	return []byte(`{"model":"claude-sonnet-4-5","metadata":{"user_id":` + strconvQuote(uid) + `}}`)
}

func extractSessionID(t *testing.T, body []byte) string {
	t.Helper()
	uid := gjsonGetString(body, "metadata.user_id")
	require.NotEmpty(t, uid, "body should carry metadata.user_id")
	parsed := ParseMetadataUserID(uid)
	require.NotNil(t, parsed, "metadata.user_id must be parseable")
	return parsed.SessionID
}

// Test 1 — Same account, different users, same clientSessionID:
// device_id stays per-account (identical), session_id diverges.
func TestRewriteUserID_SameAccountDifferentUsers_SameDevice_DifferentSessions(t *testing.T) {
	svc := NewIdentityService(newFakeIdentityCache())
	const accountID int64 = 42
	const clientSessionID = "7578cf37-aaca-46e4-a45c-71285d9dbb83"
	deviceID := "d61f76d0730d2b920763648949bad5c79742155c27037fc77ac3f9805cb90169"

	body := buildMetadataBody(t, deviceID, "", clientSessionID, "2.1.111")
	ua := "claude-cli/2.1.111 (external, cli)"

	u1Body, err := svc.RewriteUserID(context.Background(), body, accountID, "acc-uuid", deviceID, ua, 101)
	require.NoError(t, err)
	u2Body, err := svc.RewriteUserID(context.Background(), body, accountID, "acc-uuid", deviceID, ua, 202)
	require.NoError(t, err)

	u1 := ParseMetadataUserID(gjsonGetString(u1Body, "metadata.user_id"))
	u2 := ParseMetadataUserID(gjsonGetString(u2Body, "metadata.user_id"))
	require.NotNil(t, u1)
	require.NotNil(t, u2)
	require.Equal(t, u1.DeviceID, u2.DeviceID, "device_id must match — shared upstream account = same device")
	require.NotEqual(t, u1.SessionID, u2.SessionID, "session_id must differ when userID differs")
}

// Test 2 — Same user opens two distinct `claude` conversations:
// different clientSessionIDs produce different upstream session_ids.
func TestRewriteUserID_SameUserMultipleClientSessions_DifferentSessions(t *testing.T) {
	svc := NewIdentityService(newFakeIdentityCache())
	const accountID int64 = 42
	const userID int64 = 7
	deviceID := "d61f76d0730d2b920763648949bad5c79742155c27037fc77ac3f9805cb90169"
	ua := "claude-cli/2.1.111 (external, cli)"

	bodyA := buildMetadataBody(t, deviceID, "", "11111111-2222-4333-8444-555555555555", "2.1.111")
	bodyB := buildMetadataBody(t, deviceID, "", "66666666-7777-4888-8999-aaaaaaaaaaaa", "2.1.111")

	outA, err := svc.RewriteUserID(context.Background(), bodyA, accountID, "acc-uuid", deviceID, ua, userID)
	require.NoError(t, err)
	outB, err := svc.RewriteUserID(context.Background(), bodyB, accountID, "acc-uuid", deviceID, ua, userID)
	require.NoError(t, err)

	require.NotEqual(t, extractSessionID(t, outA), extractSessionID(t, outB),
		"two separate CC conversations for the same user must map to distinct upstream session_ids")
}

// Test 3 — Same (account, user, clientSessionID) across many calls is stable.
// Covers the subagent-fanout / `/resume` case: main CC + subagents share the
// parent conversation's sessionId, so all outbound session_ids must match.
// Stability also implies no Redis dependency (we don't prime the fake cache).
func TestRewriteUserID_SameUserSameClientSession_StableSession(t *testing.T) {
	svc := NewIdentityService(newFakeIdentityCache())
	const accountID int64 = 42
	const userID int64 = 7
	const clientSessionID = "cccccccc-dddd-4eee-8fff-000000000000"
	deviceID := "d61f76d0730d2b920763648949bad5c79742155c27037fc77ac3f9805cb90169"
	ua := "claude-cli/2.1.111 (external, cli)"
	body := buildMetadataBody(t, deviceID, "", clientSessionID, "2.1.111")

	var sessions []string
	for i := 0; i < 5; i++ {
		out, err := svc.RewriteUserID(context.Background(), body, accountID, "acc-uuid", deviceID, ua, userID)
		require.NoError(t, err)
		sessions = append(sessions, extractSessionID(t, out))
	}
	for i := 1; i < len(sessions); i++ {
		require.Equal(t, sessions[0], sessions[i],
			"same (accountID, userID, clientSessionID) must deterministically produce the same upstream session_id")
	}
}

// Test 4 — userID == 0 falls back to the legacy 2-part seed so
// unauthenticated / internal callers see zero behavior change.
func TestRewriteUserID_UserIDZero_FallsBackToDeterministicSeed(t *testing.T) {
	svc := NewIdentityService(newFakeIdentityCache())
	const accountID int64 = 42
	const clientSessionID = "11111111-2222-4333-8444-555555555555"
	deviceID := "d61f76d0730d2b920763648949bad5c79742155c27037fc77ac3f9805cb90169"
	ua := "claude-cli/2.1.111 (external, cli)"
	body := buildMetadataBody(t, deviceID, "", clientSessionID, "2.1.111")

	out1, err := svc.RewriteUserID(context.Background(), body, accountID, "acc-uuid", deviceID, ua, 0)
	require.NoError(t, err)
	out2, err := svc.RewriteUserID(context.Background(), body, accountID, "acc-uuid", deviceID, ua, 0)
	require.NoError(t, err)
	require.Equal(t, extractSessionID(t, out1), extractSessionID(t, out2),
		"userID == 0 path must remain deterministic across calls")

	// Cross-check: seed = sha256(accountID::sessionTail) UUIDv4 — recompute and compare.
	expected := generateUUIDFromSeed(fmtSeedLegacy(accountID, clientSessionID))
	require.Equal(t, expected, extractSessionID(t, out1),
		"userID == 0 session must equal the legacy 2-part seed's UUID")
}

// Test 5 — Mimic path looks up the per-(user, account) cached UUID on hit and
// reuses it on the next call (content hash is ignored when userID > 0).
func TestBuildOAuthMetadataUserID_UsesPerUserSessionCache(t *testing.T) {
	cache := newFakeIdentityCache()
	svc := &GatewayService{identityService: NewIdentityService(cache)}

	account := &Account{
		ID:   42,
		Type: AccountTypeOAuth,
		Extra: map[string]any{
			"account_uuid":   "acc-uuid",
			"claude_user_id": "deviceabc",
		},
	}
	// Two different parsed requests with different content to make the
	// content-hash seeded session *would* vary. With the per-user cache
	// in play, they must not.
	parsedA := &ParsedRequest{Model: "claude-sonnet-4-5", System: []any{"alpha"}}
	parsedB := &ParsedRequest{Model: "claude-sonnet-4-5", System: []any{"beta"}}
	fp := &Fingerprint{ClientID: "deviceabc", UserAgent: "claude-cli/2.1.111 (external, cli)"}

	ctx := context.Background()
	uid1 := svc.buildOAuthMetadataUserID(ctx, parsedA, account, fp, 77)
	uid2 := svc.buildOAuthMetadataUserID(ctx, parsedB, account, fp, 77)
	require.NotEmpty(t, uid1)
	require.Equal(t, uid1, uid2, "per-user cache must yield the same session_id across distinct prompts")

	// Different user on the same account must diverge.
	uid3 := svc.buildOAuthMetadataUserID(ctx, parsedA, account, fp, 88)
	require.NotEqual(t, uid1, uid3, "different userID must yield a different session_id")
}

// Test 6 — Every mimic call refreshes the cache TTL by calling SetUserSessionID.
func TestBuildOAuthMetadataUserID_CacheTTLRefreshed(t *testing.T) {
	cache := newFakeIdentityCache()
	svc := &GatewayService{identityService: NewIdentityService(cache)}

	account := &Account{
		ID:    42,
		Type:  AccountTypeOAuth,
		Extra: map[string]any{"account_uuid": "acc-uuid", "claude_user_id": "deviceabc"},
	}
	parsed := &ParsedRequest{Model: "claude-sonnet-4-5", System: []any{"alpha"}}
	fp := &Fingerprint{ClientID: "deviceabc", UserAgent: "claude-cli/2.1.111 (external, cli)"}

	for i := 0; i < 3; i++ {
		_ = svc.buildOAuthMetadataUserID(context.Background(), parsed, account, fp, 77)
	}
	require.Equal(t, 3, cache.setUserCalls[fakeUserKey(42, 77)],
		"SetUserSessionID must be called once per request to refresh the rolling idle TTL")
}

// Test 7 — Masking toggle + userID > 0 bypasses masking entirely;
// userID == 0 keeps legacy masking behavior.
func TestRewriteUserIDWithMasking_SkippedWhenUserIDPositive(t *testing.T) {
	cache := newFakeIdentityCache()
	svc := NewIdentityService(cache)

	account := &Account{
		ID:       42,
		Platform: PlatformAnthropic,
		Type:     AccountTypeOAuth,
		Extra:    map[string]any{"session_id_masking_enabled": true},
	}
	deviceID := "d61f76d0730d2b920763648949bad5c79742155c27037fc77ac3f9805cb90169"
	clientSessionID := "11111111-2222-4333-8444-555555555555"
	body := buildMetadataBody(t, deviceID, "", clientSessionID, "2.1.111")
	ua := "claude-cli/2.1.111 (external, cli)"

	// userID > 0: masking must be skipped and the per-user seeded hash preserved.
	outAuth, err := svc.RewriteUserIDWithMasking(context.Background(), body, account, "acc-uuid", deviceID, ua, 77)
	require.NoError(t, err)
	authSession := extractSessionID(t, outAuth)
	// Expected session = sha256(accountID::userID::clientSessionID)-UUIDv4
	expected := generateUUIDFromSeed(fmtSeedWithUser(42, 77, clientSessionID))
	require.Equal(t, expected, authSession, "userID > 0 must retain RewriteUserID's per-user seed")
	require.Empty(t, cache.maskedSessionID[42], "masked session cache must NOT be touched when userID > 0")

	// userID == 0: legacy masking applies and overwrites with the cached (random) UUID.
	outLegacy, err := svc.RewriteUserIDWithMasking(context.Background(), body, account, "acc-uuid", deviceID, ua, 0)
	require.NoError(t, err)
	legacySession := extractSessionID(t, outLegacy)
	require.NotEqual(t, expected, legacySession, "userID == 0 legacy path must still pick up masking")
	require.NotEmpty(t, cache.maskedSessionID[42], "masked session cache must be populated on userID == 0 path")
}

// Test 8 — syncClaudeCodeSessionIDHeader always sets the header in mimic mode
// and only overwrites an existing one in real-CC mode.
func TestXClaudeCodeSessionIDSyncedInMimic(t *testing.T) {
	body := buildMetadataBody(t,
		"d61f76d0730d2b920763648949bad5c79742155c27037fc77ac3f9805cb90169",
		"",
		"abababab-cdcd-4efe-8fef-010101010101",
		"2.1.111",
	)
	wantSession := "abababab-cdcd-4efe-8fef-010101010101"

	// Mimic mode + no client header → must set.
	req1, err := http.NewRequest("POST", "https://api.anthropic.com/v1/messages", nil)
	require.NoError(t, err)
	syncClaudeCodeSessionIDHeader(req1, body, true)
	assert.Equal(t, wantSession, getHeaderRaw(req1.Header, "X-Claude-Code-Session-Id"),
		"mimic mode must always set the header even when absent on the client")

	// Mimic mode + stale client header → must overwrite.
	req2, err := http.NewRequest("POST", "https://api.anthropic.com/v1/messages", nil)
	require.NoError(t, err)
	setHeaderRaw(req2.Header, "X-Claude-Code-Session-Id", "stale-should-be-replaced")
	syncClaudeCodeSessionIDHeader(req2, body, true)
	assert.Equal(t, wantSession, getHeaderRaw(req2.Header, "X-Claude-Code-Session-Id"))

	// Real-CC mode + no client header → must NOT set (client opted out).
	req3, err := http.NewRequest("POST", "https://api.anthropic.com/v1/messages", nil)
	require.NoError(t, err)
	syncClaudeCodeSessionIDHeader(req3, body, false)
	assert.Equal(t, "", getHeaderRaw(req3.Header, "X-Claude-Code-Session-Id"),
		"real-CC mode must not introduce a header the client did not send")

	// Real-CC mode + existing client header → must overwrite to the canonical body session_id.
	req4, err := http.NewRequest("POST", "https://api.anthropic.com/v1/messages", nil)
	require.NoError(t, err)
	setHeaderRaw(req4.Header, "X-Claude-Code-Session-Id", "client-sent-stale")
	syncClaudeCodeSessionIDHeader(req4, body, false)
	assert.Equal(t, wantSession, getHeaderRaw(req4.Header, "X-Claude-Code-Session-Id"))
}

// fmtSeedLegacy / fmtSeedWithUser mirror the seed formats in identity_service.go
// so tests can recompute the expected UUIDv4 without exporting helpers.
func fmtSeedLegacy(accountID int64, sessionTail string) string {
	return fmt.Sprintf("%d::%s", accountID, sessionTail)
}

func fmtSeedWithUser(accountID, userID int64, sessionTail string) string {
	return fmt.Sprintf("%d::%d::%s", accountID, userID, sessionTail)
}

func gjsonGetString(body []byte, path string) string {
	return gjson.GetBytes(body, path).String()
}
