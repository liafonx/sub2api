# Fork Changelog (liafonx/sub2api)

Patches not in upstream (`Wei-Shaw/sub2api`).

---

## Active Patches

### Patch 1: TLS Fingerprint Registry Fix

**Problem**: `InitGlobalRegistry()` was never called — config profiles were silently ignored and only the built-in default was used.

**Fix**: Call `InitGlobalRegistry(&cfg.Gateway.TLSFingerprint)` in `NewHTTPUpstream()`.

**Files**: `backend/internal/repository/http_upstream.go`

**Upstream status**: NOT fixed as of v0.1.85. PR submitted: https://github.com/Wei-Shaw/sub2api/pull/611

**Profile selection**: Profiles are selected deterministically: `accountID % numProfiles` (sorted alphabetically by key name).

To override the built-in default, use the key `claude_cli_v2` in config.yaml:

```yaml
gateway:
  tls_fingerprint:
    enabled: true
    profiles:
      claude_cli_v2:
        name: "Your Custom Profile Name"
        cipher_suites: [...]
        curves: [...]
        point_formats: [...]
```

---

### Patch 2: HTTP/2 Upstream (added 2026-03-02)

**Problem**: Go's standard `http.Transport` with `ForceAttemptHTTP2: true` breaks when using a custom `DialTLSContext` returning `*utls.UConn`. Go's HTTP/2 handler does a `*tls.Conn` type assertion that silently fails, causing the server (which agreed to h2 via ALPN) to send HTTP/2 binary frames while the client parses them as HTTP/1.x — 100% request failures.

**Fix**: `NewH2RoundTripper` in `h2_roundtripper.go`:
1. First request to a host: dials with utls, reads `NegotiatedProtocol` from TLS state
2. If `"h2"`: creates `golang.org/x/net/http2.Transport` (accepts `net.Conn`, no `*tls.Conn` assertion)
3. If other: creates `http.Transport{ForceAttemptHTTP2: false}` with existing pool settings
4. Caches the transport per host — all subsequent requests skip the probe

**Files**:

| File | Change |
|------|--------|
| `backend/internal/pkg/tlsfingerprint/h2_roundtripper.go` | **NEW** — Hybrid protocol-detecting RoundTripper |
| `backend/internal/pkg/tlsfingerprint/h2_roundtripper_test.go` | **NEW** — Unit tests |
| `backend/internal/pkg/tlsfingerprint/dialer.go` | ALPN changed from `["http/1.1"]` to `["h2", "http/1.1"]` |
| `backend/internal/repository/http_upstream.go` | `buildUpstreamTransportWithTLSFingerprint` now returns `http.RoundTripper` |

`golang.org/x/net/http2` was already a transitive dependency — no go.mod changes needed.

**Confirmed impact** (verified 2026-03-03): HTTP/2 multiplexing active — `h2_transport_created host=api.anthropic.com:443` observed on first request. N concurrent requests share 1 TCP+TLS connection vs N separate. JA3 fingerprint gains `h2` in ALPN, matching Node.js v22 behavior.

**Verify after deploy**:

```bash
# Should appear once per upstream host on first request:
grep "h2_transport_created\|h1_transport_created" /usr/local/var/log/sub2api/stderr.log

# Should NOT appear:
grep "malformed HTTP\|transport: received unexpected" /usr/local/var/log/sub2api/stderr.log
```

---

### Patch 3: Per-User Quota Allocation (added 2026-03-08)

**Purpose**: Prevents a single heavy user from exhausting an account's 5h window budget. Splits the remaining budget equally among currently active users, with epoch-based recalculation on user join/leave and 1-minute idle timeout.

**Files**:

| File | Change |
|------|--------|
| `backend/internal/service/user_quota_service.go` | **NEW** — `UserQuotaChecker` + `UserQuotaCache` interfaces; service implementation |
| `backend/internal/repository/user_quota_cache.go` | **NEW** — Redis implementation |

**Redis key schema**:

```
user_quota:active:{accountID}              → Sorted Set (member=userID, score=lastActivityMs)
user_quota:cost:{accountID}:{epoch}:{userID} → String (INCRBYFLOAT, 6h TTL)
user_quota:meta:{accountID}               → Hash (epoch, per_user_limit, per_user_sticky_reserve, active_count, 6h TTL)
```

**Algorithm (three-zone)**:
- Green (`userCost < perUserLimit`): allow all
- Yellow (`userCost < perUserLimit + perUserStickyReserve`): allow only sticky sessions
- Red (above): block with 429

**Recalculation triggers**: user joins (new `RegisterActivity`), idle cleanup ticker (every 15s removes users idle >60s).

**Enable per account**: set `account.Extra["user_quota_enabled"] = true`. Requires `window_cost_limit > 0`.

**Integration points**:
- `gateway_handler.go`: `RegisterUserActivity` called after account selection; `CheckUserQuotaForAccount` called before forwarding
- `gateway_service.go` `RecordUsage`: `IncrementUserCost` called after cost is computed
- `wire_gen.go`: `NewUserQuotaCache` → `NewUserQuotaService` → `SetUserQuotaChecker` + 15s cleanup ticker

**Frontend**: Toggle in Create/Edit Account modals under "Quota Control" section (Anthropic OAuth/SetupToken accounts only, disabled when Window Cost Limit is off).

---

### Patch 4: Full X25519MLKEM768 Support (added 2026-03-13)

**Purpose**: Sends both X25519MLKEM768 and X25519 key shares upfront (matching Chrome 136+), eliminating HRR round-trips.

**Files**: `backend/internal/pkg/tlsfingerprint/dialer.go`

**Details**: `KeyShareExtension` sends both `{X25519MLKEM768}` and `{X25519}` key shares; `SupportedCurvesExtension` advertises curve ID 4588.

**Note**: Requires utls v1.8.2+ (pinned in go.mod). No workarounds (`safeCurvePreferences`, `GenericExtension`, `serializeSupportedGroups`) are needed — utls v1.8.2 handles X25519MLKEM768 key share generation correctly.

---

### Patch 5: TLS Profile Cache Key Fix (added 2026-03-13)

**Purpose**: Profile key was missing from the TLS client cache key, causing all accounts to share the same transport regardless of their configured TLS fingerprint profile.

**Files**:
- `backend/internal/pkg/tlsfingerprint/registry.go`
- `backend/internal/repository/http_upstream.go`
- `backend/internal/repository/claude_usage_service.go`
- `backend/internal/service/account_usage_service.go`

---

### Patch 6: Peak Usage Log (added 2026-03-25)

**Purpose**: Records per-account peak concurrent usage. Stores the highest observed concurrent request count per account in a rolling window, queryable from the admin UI.

**Files**:

| File | Change |
|------|--------|
| `backend/internal/service/peak_usage_service.go` | **NEW** — `PeakUsageLogger` interface; service implementation |
| `backend/internal/service/peak_usage_cache.go` | **NEW** — Cache interface definitions |
| `backend/internal/repository/peak_usage_cache.go` | **NEW** — Redis implementation |
| `backend/internal/handler/admin/peak_usage_handler.go` | **NEW** — Admin API handler |
| `backend/ent/schema/peak_usage.go` | **NEW** — Ent schema for persistence |

---

### Patch 7: Claude Code Version Detection

**Purpose**: Polls the npm registry for the published stable `@anthropic-ai/claude-code` version. When the published version changes, triggers the CC Probe service to re-capture headers from the new binary version.

**Files**: `backend/internal/service/claude_code_version_detect_service.go`

---

### Patch 8: CC Probe Service (added 2026-03-25)

**Purpose**: Captures real Claude Code request headers via a local `mitmproxy` intercept of the installed `claude` binary. Enables sub2api to replay an authentic header set (User-Agent, X-Stainless-*, etc.) for each installed CC version, keeping mimic-mode headers in sync automatically.

**Dependency**: `mitmproxy` must be installed on the machine running sub2api (`pip install mitmproxy`). The service is a no-op when `cc_probe.enabled: false` (default).

**Files**:

| File | Change |
|------|--------|
| `backend/internal/service/cc_probe_service.go` | **NEW** — `CCProbeService`; periodic version check; mitmproxy-based capture; fallback file |
| `backend/internal/repository/cc_probe_cache.go` | **NEW** — Redis-backed `CCProbeCache` (90-day TTL) |
| `backend/internal/config/config.go` | Added `CCProbeConfig` struct + `viper.SetDefault` entries |
| `backend/internal/handler/admin/system_handler.go` | Added `GetCCProbeStatus`, `GetCCProbeConfig`, `TriggerCCProbe`, `GetProbePrompt`, `UpdateProbePrompt` |
| `backend/internal/server/routes/admin.go` | Added cc-probe routes under `/system/cc-probe` |
| `backend/internal/handler/wire.go` | Wired `CCProbeService` into `SystemHandler` |
| `backend/internal/wire_gen.go` | Manually wired `NewCCProbeCache` → `NewCCProbeService` → `CCProbeService.Start()` |
| `backend/internal/service/setting_service.go` | Added `GetProbePrompt`/`SetProbePrompt` methods |
| `frontend/src/components/admin/PeakUsageModal.vue` | CC probe status card (light-mode text fix) |
| `frontend/src/views/admin/SettingsView.vue` | CC Probe config panel + probe prompt input + trigger button |

**Config**:

```yaml
cc_probe:
  enabled: true
  cc_binary_path: claude          # path to claude binary (default: "claude")
  auto_update_cc: false           # run "claude update" before each probe
  update_command: ""              # override update command
  check_interval_hours: 4        # version check interval
  probe_port: 8999               # mitmproxy listen port
```

**Upstream conflict risk**: MEDIUM-HIGH — `system_handler.go`, `handler/wire.go`, `wire_gen.go`, and `setting_service.go` all change frequently upstream.

**Verification**:

```bash
ls backend/internal/service/cc_probe_service.go
grep cc-probe backend/internal/server/routes/admin.go
```

---

### Patch 9: Provider Routing (added 2026-03-25)

**Purpose**: Optionally rejects requests where the model's `litellm_provider` does not match the account's platform. Prevents e.g. OpenAI models being routed to Anthropic accounts. Off by default (`enforce_provider_routing: false`).

**Files**:

| File | Change |
|------|--------|
| `backend/internal/service/provider_routing.go` | **NEW** — `EnforceProviderRouting` inline check (33 lines) |
| `backend/internal/service/gateway_service.go` | Calls `EnforceProviderRouting` when `pricing.enforce_provider_routing: true` |
| `backend/internal/config/config.go` | `PricingConfig.EnforceProviderRouting bool` field |

**Config**:

```yaml
pricing:
  enforce_provider_routing: false  # default off; set true to enable
```

**Upstream conflict risk**: LOW — small inline check + new file; `gateway_service.go` changes are common but the hook is a single conditional.

**Verification**:

```bash
ls backend/internal/service/provider_routing.go
```

---

### Patch 10: CC Trait Registry & Claude Code Validator Enhancements (added 2026-03-26)

**Context**: Upstream already provides `ClaudeCodeValidator` (321 lines) with basic validation: UA pattern matching, system prompt prefix similarity scoring, and non-empty header checks. This patch adds a self-updating trait registry and enhances the validator with dynamic, registry-backed validation.

**CCTraitRegistry** (pure fork): Single source of truth for expected CC client traits. Loads from Redis (primary) or local file (fallback) on startup. Updated when:
- CC Probe Service captures a new version's headers/body traits (`UpdateFromProbe`)
- Prompt archive is downloaded from tweakcc GitHub repo (`EnrichFromPromptArchive`)

Snapshot contains: `ExpectedHeaderKeys`, `BetaFlags` (+ pre-computed `BetaFlagSet`), `XAppValue`, `SystemPromptPrefixes`, `Version`, `UpdatedAt`. Persists to Redis and local JSON file. Snapshots are immutable after creation — new snapshots are swapped atomically.

**ClaudeCodeValidator enhancements** (on top of upstream):
- `*CCTraitRegistry` field for dynamic trait validation
- `freshSnapshot()` method to check registry staleness (<7 days)
- Exact `X-App` header match against `snap.XAppValue` when registry is fresh
- `anthropic-beta` flag-set validation against `snap.BetaFlagSet`
- `logHeaderCoverage()` debug logging for header coverage metrics
- Relaxed fallback when registry is stale (non-empty checks only)

**Files**:

| File | Change |
|------|--------|
| `backend/internal/service/cc_trait_registry.go` | **NEW** — `CCTraitRegistry`, `CCTraitSnapshot`, prompt archive download, Redis+file persistence |
| `backend/internal/service/cc_trait_registry_test.go` | **NEW** — Unit tests |
| `backend/internal/repository/cc_trait_registry_cache.go` | **NEW** — Redis implementation of `CCTraitRegistryCache` |
| `backend/internal/service/claude_code_validator.go` | MODIFIED — enhanced with `CCTraitRegistry` integration (+89 lines vs upstream) |
| `backend/internal/service/claude_code_validator_test.go` | **NEW** — Unit tests |
| `backend/internal/handler/gateway_helper.go` | MODIFIED — `SetClaudeCodeValidator` global wiring |
| `backend/cmd/server/wire_gen.go` | MODIFIED — `NewCCTraitRegistryCache` → `NewCCTraitRegistry` → `NewClaudeCodeValidator` → `SetClaudeCodeValidator` |

**Integration**: `CCProbeService.SetTraitRegistry(r)` feeds probe results into the registry. The validator is called in the gateway handler to gate access for Claude Code-only accounts.

---

### Patch 11: Surgical Thinking Block Signature Fix (added 2026-03-26)

**Context**: Upstream already provides `gateway_request.go` (1054 lines) with `ParsedRequest`, `ParseGatewayRequest`, `FilterThinkingBlocks`, `FilterThinkingBlocksForRetry`, `FilterSignatureSensitiveBlocksForRetry`, and `RectifyThinkingBudget`. The upstream retry strategy is blunt — it strips all thinking content on signature errors.

**Problem**: When sub2api rotates which Anthropic account handles a multi-turn conversation, historical thinking blocks carry signatures bound to the previous account. Anthropic rejects with `"invalid signature in thinking block at messages.105.content.0"`. The upstream retry strips ALL thinking content, degrading model quality.

**Fork addition**: Surgical single-block removal as Stage 0, before the existing blunt strategies:

1. **Stage 0 — Surgical removal** (fork-only): `SurgicallyRemoveInvalidThinkingBlock` parses the exact `messages.X.content.Y` path from the error message and removes only that one invalid block, preserving all others. `parseThinkingBlockPath` supports both dot and bracket notation. `isExactSignatureError` gates entry to the surgical path.
2. **Stage 1 — Full thinking downgrade** (upstream): Converts `thinking` blocks to `text`, drops `redacted_thinking`, strips `clear_thinking_20251015` context management strategies.
3. **Stage 2 — Tool block downgrade** (upstream): Additionally converts `tool_use`/`tool_result` blocks to text when Stage 1 still fails.

A `badThinkingPathCache` (30-minute in-process gocache keyed by conversation fingerprint via xxhash) remembers surgically removed block paths so subsequent requests in the same conversation pre-strip them before the upstream call.

**Files**:

| File | Change |
|------|--------|
| `backend/internal/service/gateway_request.go` | MODIFIED — added `SurgicallyRemoveInvalidThinkingBlock`, `parseThinkingBlockPath`, `isExactSignatureError` |
| `backend/internal/service/gateway_request_test.go` | MODIFIED — added tests for surgical removal |
| `backend/internal/service/gateway_service.go` | MODIFIED — `badThinkingPathCache` field, surgical retry loop, cache helpers |

---

### Patch 12: Probe-Aware Identity Defaults (added 2026-03-26)

**Context**: Upstream already provides `IdentityService` with per-account fingerprint caching, `RewriteUserID` (SHA256 session derivation), `RewriteUserIDWithMasking` (15-min rotating UUID), and `ApplyFingerprint` (header injection). This patch extends it with probe-aware defaults and minor fixes.

**Fork changes on top of upstream `identity_service.go`**:
- `SetCCProbeService` + `resolveDefaults()`: uses CC Probe Service to source UA/version defaults from real captured headers instead of hardcoded static values
- `GetFingerprint` read-only accessor (used by account test service)
- ClientID repair: auto-generates ClientID for legacy entries that were cached before ClientID was introduced
- Mac Mini deployment defaults: `StainlessOS: "MacOS"`, `RuntimeVersion: "v24.3.0"`
- Header casing: `req.Header.Set()` instead of `setHeaderRaw()` (simpler, HTTP/2 normalizes case anyway)

Also fixes OpenAI OAuth token refresh to pass `client_id` from stored credentials.

**Files**:

| File | Change |
|------|--------|
| `backend/internal/service/identity_service.go` | MODIFIED — probe-aware defaults, ClientID repair, Mac Mini defaults |
| `backend/internal/service/account_test_service.go` | MODIFIED — `SetIdentityService` injector for per-account fingerprint lookup during probes |
| `backend/internal/service/oauth_service.go` | MODIFIED — `OpenAIOAuthClient` interface gains `RefreshTokenWithClientID` |
| `backend/internal/service/token_refresher.go` | MODIFIED — reads `client_id` from credentials and passes to refresh |
| `backend/internal/handler/admin/account_handler.go` | MODIFIED — identity-aware account test endpoint |
| `backend/cmd/server/wire_gen.go` | MODIFIED — `accountTestService.SetIdentityService(identityService)` |

---

## Verification

Run after every upstream merge to confirm patches survived:

```bash
# Patch 1: TLS registry init
grep InitGlobalRegistry backend/internal/repository/http_upstream.go

# Patch 2: HTTP/2 upstream
grep '"h2"' backend/internal/pkg/tlsfingerprint/dialer.go
ls backend/internal/pkg/tlsfingerprint/h2_roundtripper.go

# Patch 3: Per-user quota
ls backend/internal/service/user_quota_service.go
ls backend/internal/repository/user_quota_cache.go

# Patch 4: X25519MLKEM768 key shares
grep X25519MLKEM768 backend/internal/pkg/tlsfingerprint/dialer.go

# Patch 5: TLS profile cache key
grep profileKey backend/internal/pkg/tlsfingerprint/registry.go

# Patch 6: Peak usage log
ls backend/internal/service/peak_usage_service.go
ls backend/internal/handler/admin/peak_usage_handler.go

# Patch 7: Claude Code version detection
ls backend/internal/service/claude_code_version_detect_service.go

# Patch 8: CC Probe Service
ls backend/internal/service/cc_probe_service.go
grep cc-probe backend/internal/server/routes/admin.go

# Patch 9: Provider Routing
ls backend/internal/service/provider_routing.go

# Patch 10: CC Trait Registry & Claude Code Validator
ls backend/internal/service/cc_trait_registry.go
ls backend/internal/service/claude_code_validator.go
grep SetClaudeCodeValidator backend/internal/handler/gateway_helper.go

# Patch 11: Surgical thinking block signature fix
ls backend/internal/service/gateway_request.go
grep badThinkingPathCache backend/internal/service/gateway_service.go

# Patch 12: Fingerprint-sourced identity consistency
ls backend/internal/service/identity_service.go
grep SetIdentityService backend/cmd/server/wire_gen.go

# utls version
grep refraction-networking/utls backend/go.mod
```

Check if utls has a new stable release:

```bash
curl -s https://api.github.com/repos/refraction-networking/utls/releases/latest | grep tag_name
```

## Notes

- **utls v1.8.2 pinned**: v1.8.2 has full X25519MLKEM768 support. Upgrade to a newer tagged release when available.
- **wire_gen.go is manually maintained**: Not generated by Wire. New dependencies are added by hand in `InitializeApp`. When resolving merge conflicts, keep upstream's `NewGatewayService` signature and fork's `userQuotaCache`/`userQuotaService` wiring.
