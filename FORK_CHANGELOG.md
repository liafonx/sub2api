# Fork Changelog (liafonx/sub2api)

Surviving fork-only patches relative to upstream release `v0.1.105` (`Wei-Shaw/sub2api`).

## Inventory Method

- **Authoritative baseline**: full tree diff of `v0.1.105..main`
- **Classification rule**: track surviving fork-only behavior and maintenance-relevant compat changes, not raw commit history
- **Reapply source of truth**: file paths, symbols, config keys, routes, migrations, and verification commands
- **Non-authoritative metadata**: commit SHAs may be mentioned for context, but they are not required to reapply a patch later
- **Excluded noise**: local workspace artifacts such as `.cursor/`, `.playwright-cli/`, `.superpowers/`, and similar scratch files are intentionally not cataloged here

The goal of this document is to let the fork reset onto upstream and later reintroduce individual patches without relying on mutable branch ancestry.

---

## Active Patches

### Patch 1: TLS Fingerprint Registry Fix — SUPERSEDED

**Status**: SUPERSEDED as of upstream v0.1.105. Upstream replaced the static config-based profile registry with a DB-backed `TLSFingerprintProfileService`. The old `InitGlobalRegistry()` call is no longer needed — profiles are now resolved via `TLSFingerprintProfileService.GetProfileByID()`. No fork fix required.

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

**Status**: Active on main

**Purpose**: Prevents a single heavy user from exhausting an account's 5h window budget. Splits the remaining budget equally among currently active users, with epoch-based recalculation on user join/leave and configurable idle timeout.

**Files**:

| File | Change |
|------|--------|
| `backend/internal/service/user_quota_service.go` | **NEW** — `UserQuotaChecker` + `UserQuotaCache` interfaces; `userQuotaService` implementation; `QuotaZone` constants; `accountQuotaState`; cleanup ticker |
| `backend/internal/service/user_quota_service_test.go` | **NEW** — 26 table-driven tests covering all zones, concurrency, epoch isolation, window-reset detection |
| `backend/internal/repository/user_quota_cache.go` | **NEW** — Redis implementation with 5 Lua scripts |
| `backend/internal/service/account.go` | MODIFIED — `IsUserQuotaEnabled`, `GetUserQuotaIdleTimeout`, `GetWindowCostStickyReserve` helpers |
| `backend/internal/handler/dto/types.go` | MODIFIED — `UserQuotaEnabled`, `UserQuotaIdleTimeout` DTO fields |
| `backend/internal/handler/dto/mappers.go` | MODIFIED — `AccountToDTO` emits quota fields for Anthropic OAuth/SetupToken accounts |
| `backend/internal/service/gateway_service.go` | MODIFIED — `SetUserQuotaChecker`, `RegisterUserActivity`, `CheckUserQuotaForAccount`, `IncrementUserCost` calls in `RecordUsage` |
| `backend/internal/handler/gateway_handler.go` | MODIFIED — quota check after account selection (returns 429 when blocked) |
| `backend/internal/handler/admin/account_handler.go` | MODIFIED — `SetUserQuotaChecker` setter; `PerUserLimit`/`ActiveUserCount` fields on `AccountWithConcurrency`; `GetDisplayMetaBatch` calls in `List` (batch) and `buildAccountResponseWithRuntime` (single); `NotifyAccountUpdated` on admin Update |
| `backend/cmd/server/wire_gen.go` | MODIFIED — `NewUserQuotaCache` → `NewUserQuotaService` → `SetUserQuotaChecker` (gateway + account handler) + 15s cleanup ticker |
| `frontend/src/types/index.ts` | MODIFIED — `per_user_limit`, `active_user_count` optional fields on `Account` |
| `frontend/src/components/account/AccountCapacityCell.vue` | MODIFIED — per-user quota badge (blue active / gray idle) between windowCost and sessions badges |
| `frontend/src/i18n/locales/en.ts` | MODIFIED — `capacity.userQuota.active` / `capacity.userQuota.inactive` i18n strings |
| `frontend/src/i18n/locales/zh.ts` | MODIFIED — same i18n strings in Chinese |

**Redis key schema**:

```text
user_quota:active:{accountID}              → Sorted Set (member=userID, score=lastActivityMs)
user_quota:cost:{accountID}:{epoch}:{userID} → String (INCRBYFLOAT, 6h TTL)
user_quota:meta:{accountID}               → Hash (epoch, per_user_limit, per_user_sticky_reserve, active_count, 6h TTL)
```

**Lua scripts** (all in `user_quota_cache.go`):

| Script | Purpose | TOCTOU fix |
|--------|---------|------------|
| `zAddActivityScript` | ZADD GT + EXPIRE atomically; returns 1 if newly added | Prevents EXPIRE from being skipped on concurrent add |
| `zRemIdleUsersScript` | ZRANGEBYSCORE + ZREMRANGEBYSCORE atomically; returns removed userIDs | Closes race between read-idle and remove-idle |
| `bumpEpochAndSetMetaScript` | Uses `redis.call("TIME")` for epoch (ms precision); HSET + EXPIRE | Prevents epoch reuse after `DelMeta` (monotonic server clock) |
| `getQuotaCheckDataScript` | HMGET meta + GET cost key in 1 RTT; constructs cost key from epoch inside Lua | Ensures epoch and cost are read atomically |
| `atomicIncrCostScript` | HGET epoch + INCRBYFLOAT cost + EXPIRE; returns `[epoch, newTotal]` | Prevents stale-epoch cost writes during concurrent epoch bumps |

**QuotaZone constants** (`type QuotaZone = string`):

| Constant | Value | Meaning |
|----------|-------|---------|
| `QuotaZoneDisabled` | `"disabled"` | Feature not enabled; pass-through |
| `QuotaZoneNoEpoch` | `"no_epoch"` | No meta hash yet; pass-through |
| `QuotaZoneRedisError` | `"redis_error"` | Redis failure; fail-open |
| `QuotaZoneGreen` | `"green"` | `userCost < perUserLimit` — allowed |
| `QuotaZoneYellowSticky` | `"yellow_sticky"` | In yellow zone AND sticky — allowed |
| `QuotaZoneYellowNonStick` | `"yellow_non_sticky"` | In yellow zone AND not sticky — blocked |
| `QuotaZoneRed` | `"red"` | Above all limits — blocked |

**Window-reset detection**: `accountQuotaState.lastWindowStartMs` tracks the 5h billing window start at last recalculation. When `RegisterActivity` or the cleanup ticker detects the window has rolled forward, a full `recalculateQuotas` is triggered, bumping epoch and resetting per-user limits.

**Epoch derivation**: Uses Redis `TIME` command inside `bumpEpochAndSetMetaScript` (`t[1]*1000 + floor(t[2]/1000)` = ms precision). This prevents epoch reuse after `DelMeta` — unlike `HINCRBY` which would restart from 0.

**Account helpers** (in `account.go`):

| Method | Extra key | Default |
|--------|-----------|---------|
| `IsUserQuotaEnabled()` | `user_quota_enabled` | `false` (requires `IsAnthropicOAuthOrSetupToken`) |
| `GetUserQuotaIdleTimeout()` | `user_quota_idle_timeout` | 60 seconds |
| `GetWindowCostStickyReserve()` | `window_cost_sticky_reserve` | 10.0 |

**DTO layer** (`dto/types.go`):
- `UserQuotaEnabled *bool` — emitted when enabled on Anthropic OAuth/SetupToken accounts
- `UserQuotaIdleTimeout *int` — seconds, emitted alongside enabled flag

**Algorithm (three-zone)**:
- Green (`userCost < perUserLimit`): allow all
- Yellow (`userCost < perUserLimit + perUserStickyReserve`): allow only sticky sessions
- Red (above): block with 429

**Recalculation triggers**: user joins (new `RegisterActivity`), idle cleanup ticker (every 15s removes users idle >idle_timeout), window reset detected, admin account update (`NotifyAccountUpdated`).

**Enable per account**: set `account.Extra["user_quota_enabled"] = true`. Requires `window_cost_limit > 0`.

**Integration points**:
- `gateway_handler.go`: `RegisterUserActivity` called after account selection; `CheckUserQuotaForAccount` called before forwarding (returns HTTP 429 when blocked)
- `gateway_service.go` `RecordUsage` + `RecordUsageWithLongContext`: `IncrementUserCost` called after cost is computed
- `account_handler.go`: `SetUserQuotaChecker` wired via setter; `GetDisplayMetaBatch` enriches List (batch) and single-account endpoints; `NotifyAccountUpdated` called after admin Update to immediately recalculate quota on settings change
- `wire_gen.go`: `NewUserQuotaCache` → `NewUserQuotaService` → `SetUserQuotaChecker` (gateway + account handler) + 15s cleanup ticker

**Frontend**:
- Toggle in Create/Edit Account modals under "Quota Control" section (Anthropic OAuth/SetupToken accounts only, disabled when Window Cost Limit is off)
- Per-user quota badge in `AccountCapacityCell.vue`: blue badge when active (`{activeCount} · ${perUserLimit}`), gray badge when idle (`Q`), hidden when quota disabled

**Reapply markers**:
- `UserQuotaChecker`
- `UserQuotaCache`
- `QuotaZoneGreen`
- `zAddActivityScript`
- `bumpEpochAndSetMetaScript`
- `getQuotaCheckDataScript`
- `atomicIncrCostScript`
- `IsUserQuotaEnabled`
- `GetUserQuotaIdleTimeout`
- `user_quota_enabled`
- `GetDisplayMetaBatch`
- `NotifyAccountUpdated`
- `showUserQuotaActive`

**Verification**:

```bash
ls backend/internal/service/user_quota_service.go
ls backend/internal/repository/user_quota_cache.go
grep QuotaZoneGreen backend/internal/service/user_quota_service.go
grep zAddActivityScript backend/internal/repository/user_quota_cache.go
grep bumpEpochAndSetMetaScript backend/internal/repository/user_quota_cache.go
grep IsUserQuotaEnabled backend/internal/service/account.go
grep UserQuotaEnabled backend/internal/handler/dto/types.go
grep SetUserQuotaChecker backend/cmd/server/wire_gen.go
grep GetDisplayMetaBatch backend/internal/handler/admin/account_handler.go
grep NotifyAccountUpdated backend/internal/handler/admin/account_handler.go
grep showUserQuotaActive frontend/src/components/account/AccountCapacityCell.vue
```

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
- `backend/internal/pkg/tlsfingerprint/profile_identity.go` (renamed from `registry.go` in v0.1.105)
- `backend/internal/repository/http_upstream.go`
- `backend/internal/repository/claude_usage_service.go`
- `backend/internal/service/account_usage_service.go`

---

### Patch 6: Peak Usage Log (added 2026-03-25)

**Status**: Active on main

**Purpose**: Tracks all-time peak values for three metrics (concurrency, sessions, RPM) for both accounts and users. Redis stores live peaks via atomic Lua compare-and-set; a 5-minute TimingWheel flush persists to Postgres with `GREATEST()` upsert semantics. Admin UI shows peaks per entity with reset capability.

**Files**:

| File | Change |
|------|--------|
| `backend/internal/service/peak_usage_service.go` | **NEW** — `PeakUsageService`, `PeakDTO`, flush/upsert logic, `GREATEST()` SQL |
| `backend/internal/service/peak_usage_cache.go` | **NEW** — `PeakUsageCache` interface, `PeakValues` struct, entity type/field constants, `updatePeakIfGreaterAsync` helper |
| `backend/internal/repository/peak_usage_cache.go` | **NEW** — Redis implementation with `peakUpdateIfGreaterScript` Lua |
| `backend/internal/handler/admin/peak_usage_handler.go` | **NEW** — Admin API handler (GET accounts, GET users, POST reset) |
| `backend/ent/schema/peak_usage.go` | **NEW** — Ent schema (`peak_usages` table) |
| `backend/migrations/081_peak_usage.sql` | **NEW** — DB migration |
| `backend/internal/service/concurrency_service.go` | MODIFIED — `peakCache` field, `updatePeakConcurrencyAsync` after slot acquisition |
| `backend/internal/service/gateway_service.go` | MODIFIED — `SetPeakUsageCache`, RPM peak tracking, session peak tracking |
| `backend/internal/server/routes/admin.go` | MODIFIED — `registerPeakUsageRoutes` under `/peak-usage` |
| `backend/internal/service/wire.go` | MODIFIED — `ProvidePeakUsageService`, `ProvideConcurrencyService` |
| `backend/cmd/server/wire_gen.go` | MODIFIED — `NewPeakUsageCache` → `ProvidePeakUsageService` → `NewPeakUsageHandler` |
| `frontend/src/api/admin/peakUsage.ts` | **NEW** — API client (`getAccountPeaks`, `getUserPeaks`, `resetPeaks`) |
| `frontend/src/components/admin/PeakUsageModal.vue` | **NEW** — Peak usage modal with card grid and reset |
| `frontend/src/views/admin/DashboardView.vue` | MODIFIED — clickable stat cards open peak modal |
| `frontend/src/types/index.ts` | MODIFIED — `PeakUsageEntry` interface |
| `frontend/src/i18n/locales/en.ts` | MODIFIED — `peakUsage` i18n keys |
| `frontend/src/i18n/locales/zh.ts` | MODIFIED — `peakUsage` i18n keys |

**Redis key schema**:

```text
peak:account:{id}  → Hash (concurrency, sessions, rpm, reset_at)
peak:user:{id}     → Hash (concurrency, sessions, rpm, reset_at)
```

No TTL — keys are permanent until explicitly reset.

**Lua script** — `peakUpdateIfGreaterScript`: atomic compare-and-set. `HGET` current value; if `newVal > current`, `HSET`. Returns old value. Prevents race conditions when multiple goroutines observe peaks simultaneously.

**DB persistence**: 5-minute flush cycle via `TimingWheelService`. Upsert uses `GREATEST(peak_usages.{col}, EXCLUDED.{col})` for all three peak columns. `updated_at` only advances when a peak field actually increased (`peakUpdatedAtExpr` CASE expression). Zero-value entries skipped on flush to prevent Redis restarts from overwriting legitimate DB peaks.

**Integration points**:
- `ConcurrencyService.AcquireAccountSlot/AcquireUserSlot` → `updatePeakConcurrencyAsync` (concurrency metric)
- `GatewayService.IncrementAccountRPM/IncrementUserRPM` → `updatePeakAsync` (RPM metric)
- `GatewayService.TrackAccountSessionPeak/TrackUserSessionPeak` + `checkAndRegisterSession` → `UpdatePeakIfGreater` (sessions metric)

All hot-path peak updates are fire-and-forget goroutines with 3-second timeout.

**Admin API routes** (`/api/v1/admin/peak-usage`):
- `GET /accounts` — returns `[]PeakDTO` enriched with account name, platform, limits
- `GET /users` — returns `[]PeakDTO` enriched with user email
- `POST /reset` — body `{"entity_type": "account"|"user"}`, zeros Redis + DB, sets `reset_at`

**Upstream conflict risk**: MEDIUM — touches `concurrency_service.go`, `gateway_service.go`, `wire_gen.go`, admin routes.

**Reapply markers**:
- `PeakUsageCache`
- `PeakUsageService`
- `peakUpdateIfGreaterScript`
- `updatePeakIfGreaterAsync`
- `FlushPeaksFromRedis`
- `peak_usage:flush`
- `registerPeakUsageRoutes`
- `PeakUsageModal`

**Verification**:

```bash
ls backend/internal/service/peak_usage_service.go
ls backend/internal/service/peak_usage_cache.go
ls backend/internal/repository/peak_usage_cache.go
ls backend/internal/handler/admin/peak_usage_handler.go
grep peakUpdateIfGreaterScript backend/internal/repository/peak_usage_cache.go
grep registerPeakUsageRoutes backend/internal/server/routes/admin.go
grep PeakUsageModal frontend/src/components/admin/PeakUsageModal.vue
grep SetPeakUsageCache backend/internal/service/gateway_service.go
```

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
| `backend/internal/service/cc_probe_service.go` | **NEW** — `CCProbeService`; periodic version check; mitmproxy-based capture; fallback file; `SetOnFingerprintRebuild` callback (replaces former `ApplyVersionHeaders`) |
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

**Status**: Active on main

**Purpose**: Optionally rejects requests where the model's `litellm_provider` does not match the account's platform. Prevents e.g. OpenAI models being routed to Anthropic accounts. Off by default (`enforce_provider_routing: false`).

**Files**:

| File | Change |
|------|--------|
| `backend/internal/service/provider_routing.go` | **NEW** — `platformToProviders` map, `providerToPlatform` reverse index (built in `init()`), `isProviderAllowedForPlatform` function |
| `backend/internal/service/provider_routing_test.go` | **NEW** — 14 table-driven cases for `isProviderAllowedForPlatform` |
| `backend/internal/service/gateway_service_provider_routing_test.go` | **NEW** — 6 integration tests for `isModelSupportedByAccount` with provider routing |
| `backend/internal/service/gateway_service.go` | MODIFIED — `isModelSupportedByAccount` calls provider check before `NormalizeModelID` |
| `backend/internal/service/pricing_service.go` | MODIFIED — `modelProvider` field, `buildModelProviderIndex`, `GetModelProvider` |
| `backend/internal/service/pricing_service_test.go` | MODIFIED — tests for `buildModelProviderIndex` and `GetModelProvider` |
| `backend/internal/config/config.go` | MODIFIED — `PricingConfig.EnforceProviderRouting bool` field |

**Platform → provider mapping** (`platformToProviders`):

| Platform | Accepted `litellm_provider` values |
|----------|-------------------------------------|
| `anthropic` | `"anthropic"` |
| `openai` | `"openai"`, `"text-completion-openai"` |
| `gemini` | `"gemini"`, `"vertex_ai-language-models"`, `"vertex_ai-vision-models"`, `"vertex_ai-embedding-models"` |

`providerToPlatform` is the reverse index, built in `init()` by inverting `platformToProviders`. Unknown providers fail-open (return `true`).

**Pre-normalize check**: The provider routing check runs BEFORE `NormalizeModelID` in `isModelSupportedByAccount`. This is because the `modelProvider` index is keyed on LiteLLM's original (short) model names. Normalizing first would transform short names into long versioned names that may not exist in the pricing index, causing false unknowns that silently fail-open.

**PricingService integration**:
- `modelProvider map[string]string` — lowercase model name → `litellm_provider`, built by `buildModelProviderIndex` from LiteLLM pricing data on each refresh
- `GetModelProvider(modelName) string` — case-insensitive exact lookup; returns `""` for unknown models (caller treats as fail-open)

**Config**:

```yaml
pricing:
  enforce_provider_routing: false  # default off; set true to enable
```

**Upstream conflict risk**: LOW — small inline check + new file; `gateway_service.go` changes are common but the hook is a single conditional.

**Reapply markers**:
- `platformToProviders`
- `providerToPlatform`
- `isProviderAllowedForPlatform`
- `EnforceProviderRouting`
- `GetModelProvider`
- `buildModelProviderIndex`

**Verification**:

```bash
ls backend/internal/service/provider_routing.go
grep platformToProviders backend/internal/service/provider_routing.go
grep EnforceProviderRouting backend/internal/config/config.go
grep GetModelProvider backend/internal/service/pricing_service.go
grep isProviderAllowedForPlatform backend/internal/service/gateway_service.go
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
| `backend/internal/service/identity_service.go` | MODIFIED — probe-aware defaults, ClientID repair, Mac Mini defaults; owns `BuildFingerprintFromProbeAndProfile`, `RebuildAccountFingerprint`, `RebuildAllFingerprints`; `SetTLSFPProfileService` + `SetAccountRepo` setters |
| `backend/internal/service/admin_service.go` | MODIFIED — `SetOnAccountFingerprintRebuild` callback for per-account fingerprint rebuild on config change |
| `backend/internal/pkg/claude/constants.go` | MODIFIED — adds `FingerprintManagedHeaders` (static per-account) and `DynamicDefaults` (per-request) header maps, derived from `DefaultHeaders` |
| `backend/internal/service/account_test_service.go` | MODIFIED — `SetIdentityService` injector for per-account fingerprint lookup during probes |
| `backend/internal/service/oauth_service.go` | MODIFIED — `OpenAIOAuthClient` interface gains `RefreshTokenWithClientID` |
| `backend/internal/service/token_refresher.go` | MODIFIED — reads `client_id` from credentials and passes to refresh |
| `backend/internal/handler/admin/account_handler.go` | MODIFIED — identity-aware account test endpoint |
| `backend/cmd/server/wire_gen.go` | MODIFIED — `SetIdentityService`, `SetTLSFPProfileService`, `SetAccountRepo`, `SetOnFingerprintRebuild(RebuildAllFingerprints)`, `SetOnAccountFingerprintRebuild`, initial `RebuildAllFingerprints()` call |

---

### Patch 13: InfoPopup Tooltip Component (added 2026-03-30)

**Purpose**: Reusable `@floating-ui/vue` tooltip component replacing ~140 lines of duplicated inline `<Teleport>` + `getBoundingClientRect()` tooltip code in each usage view. Smart positioning (flip, shift, arrow), singleton pattern (one popup at a time), hover+click+touch support.

**Files**:

| File | Change |
|------|--------|
| `frontend/src/components/common/InfoPopup.vue` | **NEW** — Core floating tooltip: dual `<script>` blocks (module-scope singleton + setup), `@floating-ui/vue` positioning, `pointerenter`/`pointerleave` (mouse-only) + click toggle, outside-click close via capture-phase global listener with reference counting |
| `frontend/src/components/common/InfoPopup.spec.ts` | **NEW** — 9 Vitest tests: open/close, toggle, pointer events, slot rendering, floating styles, singleton behavior, listener cleanup on last unmount, destroy-while-open cleanup |
| `frontend/src/components/common/UsageCostPopup.vue` | **NEW** — Thin wrapper: cost breakdown (input/output/cache costs, per-million pricing, service tier, rate); `showAccountBilling` prop adds account multiplier + account billed rows (admin view) |
| `frontend/src/components/common/UsageTokenPopup.vue` | **NEW** — Thin wrapper: token breakdown (input/output/cache tokens with 5m/1h TTL badges, cache TTL override indicator) |
| `frontend/src/components/admin/usage/UsageTable.vue` | MODIFIED — removed ~140 lines inline Teleport tooltips + state/functions, replaced with `<UsageCostPopup>` and `<UsageTokenPopup>` |
| `frontend/src/views/user/UsageView.vue` | MODIFIED — removed ~180 lines inline Teleport tooltips + state/functions, replaced with `<UsageCostPopup>` and `<UsageTokenPopup>` |
| `frontend/package.json` | MODIFIED — added `@floating-ui/vue ^1.1.11` dependency |
| `frontend/vite.config.ts` | MODIFIED — added `vue-demi` and `@floating-ui/` to `vendor-vue` manual chunk to prevent cross-chunk TDZ circular dependency (vue-demi re-exports Vue internals; placing it in `vendor-misc` caused `ReferenceError: Cannot access '$' before initialization`) |

**Key design decisions**:
- Module-scope singleton (`closeActivePopup`, `activeContains`, `listenerCount`) in non-setup `<script lang="ts">` block — ensures only one popup open across all instances
- `data-infopopup-trigger` DOM attribute for click-outside detection (global click handler skips clicks on other triggers to let their `toggle()` handle singleton swap)
- `HelpTooltip.vue` left as-is — different use case (hover-only, fixed width, text content)
- Components imported by path, not exported from `components/common/index.ts` (domain-specific wrappers)

**Upstream conflict risk**: HIGH — upstream may rewrite tooltip implementations in usage views.

**Reapply markers**:
- `InfoPopup`
- `UsageCostPopup`
- `UsageTokenPopup`
- `@floating-ui/vue`
- `data-infopopup-trigger`
- `closeActivePopup`

**Verification**:

```bash
ls frontend/src/components/common/InfoPopup.vue
ls frontend/src/components/common/UsageCostPopup.vue
ls frontend/src/components/common/UsageTokenPopup.vue
grep InfoPopup frontend/src/components/admin/usage/UsageTable.vue
grep InfoPopup frontend/src/views/user/UsageView.vue
grep floating-ui frontend/package.json
grep vue-demi frontend/vite.config.ts
cd frontend && pnpm vitest run src/components/common/InfoPopup.spec.ts
```

---

### Patch 14: Scheduled Rate Multiplier (added 2026-03-28)

**Purpose**: Time-of-day/day-of-week/date-range rate override rules per group. Allows different billing multipliers during peak/off-peak hours, weekends, or specific date ranges. First matching rule wins; falls back to group's default `rate_multiplier`.

**Files**:

| File | Change |
|------|--------|
| `backend/internal/service/group_scheduled_rate.go` | **NEW** — `GetEffectiveRateMultiplier`, `ValidateScheduledRateConfig`, rule matching logic |
| `backend/internal/service/group_scheduled_rate_test.go` | **NEW** — Unit tests for rule matching |
| `backend/internal/service/group_scheduled_rate_validation_test.go` | **NEW** — Validation tests |
| `backend/internal/service/auth_cache_scheduled_rate_test.go` | **NEW** — Auth cache round-trip tests |
| `backend/ent/schema/group.go` | MODIFIED — added `scheduled_rate_config` JSONB field |
| `backend/internal/repository/group_repo.go` | MODIFIED — Create/Update JSON marshal for ScheduledRateConfig |
| `backend/internal/repository/api_key_repo.go` | MODIFIED — GetByKeyForAuth select + groupEntityToService round-trip |
| `backend/internal/service/admin_service.go` | MODIFIED — CreateGroupInput/UpdateGroupInput + pass-through |
| `backend/internal/handler/admin/group_handler.go` | MODIFIED — request structs + ValidateScheduledRateConfig call |
| `backend/internal/service/gateway_service.go` | MODIFIED — `GetEffectiveRateMultiplier(timezone.Now())` in billing |
| `backend/internal/service/openai_gateway_service.go` | MODIFIED — same billing change |
| `frontend/src/components/group/ScheduledRateRulesEditor.vue` | **NEW** — Vue component for rule editing |
| `frontend/src/views/admin/GroupsView.vue` | MODIFIED — ScheduledRateRulesEditor in create/edit modals |
| `frontend/src/i18n/locales/en.ts` | MODIFIED — `scheduledRate` i18n keys |
| `frontend/src/i18n/locales/zh.ts` | MODIFIED — `scheduledRate` i18n keys |

**Upstream conflict risk**: HIGH — touches group schema, handler, gateway billing, GroupsView.

---

### Patch 15: Unified Account Test Prompt (added 2026-03-27)

**Purpose**: Replaces separate probe and scheduled-test prompt knobs with a single `account_test_prompt` setting, while preserving read-time fallback from legacy keys (`probe_prompt`, `scheduled_test_prompt`).

**Files**:

| File | Change |
|------|--------|
| `backend/internal/service/domain_constants.go` | Added unified setting key and legacy fallback keys |
| `backend/internal/service/setting_service.go` | Reads/writes unified prompt; migrates from legacy fallback chain |
| `backend/internal/service/settings_view.go` | Exposes unified prompt in admin settings view model |
| `backend/internal/handler/dto/settings.go` | Adds `account_test_prompt` API field |
| `backend/internal/handler/admin/setting_handler.go` | Reads/writes unified prompt through admin settings API |
| `backend/internal/service/cc_probe_service.go` | Reads unified prompt for probe execution |
| `backend/internal/service/scheduled_test_runner_service.go` | Reads unified prompt for scheduled account tests |
| `backend/internal/service/account_test_service.go` | Threads prompt through background/manual test paths |
| `backend/internal/service/account_usage_service.go` | Preserves safe default on usage-side probe calls |
| `frontend/src/views/admin/SettingsView.vue` | Admin UI for unified account test prompt |
| `frontend/src/api/admin/settings.ts` | Settings API contract |
| `frontend/src/api/admin/system.ts` | CC probe config view exposes unified prompt |

**Why it exists**: The fork has both CC Probe and scheduled account tests. Keeping separate prompt settings duplicates configuration and makes probe/test behavior diverge for no functional gain.

**Reapply markers**:
- `SettingKeyAccountTestPrompt`
- `legacyKeyProbePrompt`
- `legacyKeyScheduledTestPrompt`
- `GetAccountTestPrompt`
- `account_test_prompt`

**Verification**:

```bash
rg -n "SettingKeyAccountTestPrompt|legacyKeyProbePrompt|legacyKeyScheduledTestPrompt|GetAccountTestPrompt|account_test_prompt" backend frontend
```

---

### Patch 16: Local Overload Admission Cooldown (added 2026-03-28)

**Purpose**: Adds instant in-process overload suppression after a 529 response so concurrent goroutines stop selecting the same overloaded account before Redis/runtime state propagates.

**Files**:

| File | Change |
|------|--------|
| `backend/internal/handler/admission.go` | **NEW** — `LocalOverloadTracker` implementation |
| `backend/internal/handler/admission_test.go` | **NEW** — concurrency and cooldown tests |
| `backend/internal/handler/failover_loop.go` | Skips locally overloaded accounts during failover |
| `backend/internal/handler/failover_loop_test.go` | Test coverage for local overload skipping |
| `backend/internal/handler/gateway_handler.go` | Installs tracker on gateway handler |
| `backend/internal/handler/gateway_handler_chat_completions.go` | Uses tracker in chat completion path |
| `backend/internal/handler/gateway_handler_responses.go` | Uses tracker in responses path |
| `backend/internal/handler/gemini_v1beta_handler.go` | Uses tracker in Gemini path |
| `backend/internal/service/setting_service.go` | Persists overload cooldown settings |
| `backend/internal/service/settings_view.go` | Exposes overload cooldown settings to admin UI |
| `backend/internal/handler/dto/settings.go` | Adds overload cooldown DTO |
| `backend/internal/handler/admin/setting_handler.go` | Admin API for overload cooldown settings |
| `frontend/src/views/admin/SettingsView.vue` | Admin UI for overload cooldown |
| `frontend/src/api/admin/settings.ts` | Settings API contract for overload cooldown |

**Why it exists**: The fork runs concurrent request selection. After one request receives a 529, waiting for shared runtime state to propagate still allows more requests to hit the same bad account. A short local cooldown closes that race window.

**Dependencies**: Complements, but does not replace, the existing runtime/Redis overload marking.

**Reapply markers**:
- `LocalOverloadTracker`
- `SkipIfOverloaded`
- `SettingKeyOverloadCooldownSettings`
- `overload_cooldown_settings`

**Verification**:

```bash
rg -n "LocalOverloadTracker|SkipIfOverloaded|SettingKeyOverloadCooldownSettings|overload_cooldown_settings" backend frontend
```

---

### Patch 17: CSP Nonce Hardening for Embedded Frontend (added 2026-03-28)

**Purpose**: Ensures all embedded frontend `<script>` tags, including Vite-generated module scripts, receive the per-request CSP nonce instead of only the injected settings script.

**Files**:

| File | Change |
|------|--------|
| `backend/internal/web/embed_on.go` | Adds `addNonceToScriptTags` and applies nonce injection to bare script tags |
| `backend/internal/web/embed_test.go` | Adds tests for bare and module script nonce injection |
| `frontend/vite.config.ts` | Keeps generated HTML compatible with runtime nonce injection |

**Why it exists**: Placeholder replacement alone only protects the injected config script. The compiled frontend still emits module script tags that must carry the same nonce to satisfy strict CSP.

**Reapply markers**:
- `NonceHTMLPlaceholder`
- `replaceNoncePlaceholder`
- `addNonceToScriptTags`

**Verification**:

```bash
rg -n "NonceHTMLPlaceholder|replaceNoncePlaceholder|addNonceToScriptTags" backend/internal/web frontend/vite.config.ts
```

---

### Patch 18: Zero Cache Read Pricing for Configurable Providers (added 2026-03-29)

**Purpose**: Anthropic doesn't charge for cache read tokens, but LiteLLM's pricing database lists a non-zero rate. This inflates reported costs. A YAML config setting zeroes out cache read pricing for specified providers.

**Files**:

| File | Change |
|------|--------|
| `backend/internal/config/config.go` | Added `ZeroCacheReadProviders []string` to `PricingConfig` |
| `backend/internal/service/billing_service.go` | Added `applyCacheReadOverride` (method), `inferProviderFromModelName` (package-level); modified `GetModelPricing` return paths |
| `backend/internal/service/billing_service_test.go` | 16 new tests (unit + integration) |

**Config**:

```yaml
pricing:
  zero_cache_read_providers:
    - anthropic
```

**How it works**:
- Dynamic path (LiteLLM data available): uses `litellmPricing.LiteLLMProvider` directly
- Fallback path (no LiteLLM): `inferProviderFromModelName` heuristic (matches "claude" → anthropic, "gpt"/"codex" → openai, "gemini" → gemini)
- Composition: build pricing → `applyModelSpecificPricingPolicy` → `applyCacheReadOverride`
- Zeros both `CacheReadPricePerToken` and `CacheReadPricePerTokenPriority`; clones struct to avoid mutation

**Upstream conflict risk**: LOW — two new functions + minor change to `GetModelPricing` return statements.

**Reapply markers**:
- `ZeroCacheReadProviders`
- `applyCacheReadOverride`
- `inferProviderFromModelName`

**Verification**:

```bash
grep ZeroCacheReadProviders backend/internal/config/config.go
grep applyCacheReadOverride backend/internal/service/billing_service.go
go test -tags unit -run "TestInferProvider|TestApplyCacheRead|TestGetModelPricing_ZeroCacheRead|TestCalculateCost_ZeroCacheRead" ./internal/service/
```

---

### Patch 19: Dynamic Cost Tracking (added 2026-03-30)

**Status**: Active on main

**Purpose**: Auto-derives 5h and 7d dollar limits from Anthropic utilization headers instead of relying on manually configured thresholds. Uses a graduated-trust algorithm: high utilization (≥5%) → `cost/utilization`; low utilization (1–5%) → capped by fallback; very low (<1%) → fallback only. Manual limits become the bootstrap fallback.

**Files**:

| File | Change |
|------|--------|
| `backend/internal/service/account.go` | MODIFIED — `WindowType` type + `Window5h`/`Window7d` constants; `IsDynamicCostEnabled`, `GetWindowCost7dLimit`, `GetWindowCost7dStickyReserve`, `GetDerived5hLimit`, `GetDerived7dLimit`, `Get7dWindowStartTime`, `HasWindowCostControl`, `GetCappedStickyReserve`, `GetSessionWindowUtilization`, `GetPassiveUsage7dUtilization` accessors |
| `backend/internal/service/gateway_service.go` | MODIFIED — `GetEffectiveWindowCostLimit`, `computeEffectiveWindowCostLimit` (pure-compute), `getWindowCostForAccount` (5h+7d), `checkWindowZone` (single cost fetch), `isAccountSchedulableForWindowCost` (dual-window check), 7d prefetch in batch scheduling |
| `backend/internal/service/ratelimit_service.go` | MODIFIED — `persistDerivedLimitsAndMilestones`, `validateMilestone` (10% boundary + recalc trigger), unified `getWindowCostForAccount`, consolidated `UpdateSessionWindow` (single UpdateExtra call), 7d window reset detection |
| `backend/internal/service/dynamic_cost_test.go` | **NEW** — Tests for accessors, `GetEffectiveWindowCostLimit`, `checkWindowZone`, manual-limit regression |
| `backend/internal/handler/admin/account_handler.go` | MODIFIED — `Effective5hLimit`, `Effective7dLimit`, `Utilization5h`, `Utilization7d` runtime fields; `enrichDynamicCostRuntime` |
| `backend/internal/handler/dto/types.go` | MODIFIED — `DynamicCostEnabled`, `WindowCost7dLimit`, `WindowCost7dStickyReserve` DTO fields |
| `backend/internal/handler/dto/mappers.go` | MODIFIED — conditional serialization of dynamic cost fields; 7d sticky reserve gated on enablement |
| `backend/internal/repository/session_limit_cache.go` | MODIFIED — 7d window cost cache (`GetWindowCost7d`, `SetWindowCost7d`, `GetWindowCost7dBatch`, `DeleteWindowCost7d`); `batchGetWindowCosts` shared helper |
| `backend/internal/service/session_limit_cache.go` | MODIFIED — 7d cache interface methods |
| `backend/cmd/server/wire_gen.go` | MODIFIED — 7d cache wiring |
| `frontend/src/types/index.ts` | MODIFIED — `dynamic_cost_enabled`, `window_cost_7d_limit`, `window_cost_7d_sticky_reserve`, `effective_5h_limit`, `effective_7d_limit`, `utilization_5h`, `utilization_7d` fields |
| `frontend/src/components/account/CreateAccountModal.vue` | MODIFIED — Dynamic Cost Tracking toggle section |
| `frontend/src/components/account/EditAccountModal.vue` | MODIFIED — Dynamic Cost Tracking toggle section |
| `frontend/src/i18n/locales/en.ts` | MODIFIED — `dynamicCost` i18n keys |
| `frontend/src/i18n/locales/zh.ts` | MODIFIED — `dynamicCost` i18n keys |

**Account Extra keys**:

| Key | Type | Purpose |
|-----|------|---------|
| `dynamic_cost_enabled` | bool | Feature toggle |
| `window_cost_7d_limit` | float64 | Manual 7d threshold (optional) |
| `window_cost_7d_sticky_reserve` | float64 | 7d sticky reserve (default 10) |
| `derived_5h_limit` | float64 | Auto-derived 5h limit |
| `derived_7d_limit` | float64 | Auto-derived 7d limit |
| `passive_usage_7d_utilization` | float64 | Sampled 7d utilization (0–1) |
| `passive_usage_7d_reset` | int64 | 7d window reset unix timestamp |
| `last_validated_5h_milestone` | int | Last 10%-boundary milestone (5h) |
| `last_validated_7d_milestone` | int | Last 10%-boundary milestone (7d) |

**Graduated-trust algorithm** (`computeEffectiveWindowCostLimit`):
- `utilization ≥ 5%`: `cost / utilization` (full trust)
- `utilization 1–5%`: `min(cost / utilization, fallback)` (capped)
- `utilization < 1%`: `fallback` (derived stored > manual > 0 fail-open)

**Milestone validation**: At each 10% utilization boundary, logs derived limit and triggers per-user quota recalculation if derived limit drifted >15% from previous checkpoint.

**Upstream conflict risk**: MEDIUM — touches `gateway_service.go`, `ratelimit_service.go`, `account_handler.go`, `wire_gen.go`.

**Reapply markers**:
- `WindowType`
- `Window5h`
- `Window7d`
- `IsDynamicCostEnabled`
- `computeEffectiveWindowCostLimit`
- `GetEffectiveWindowCostLimit`
- `persistDerivedLimitsAndMilestones`
- `validateMilestone`
- `derived_5h_limit`
- `derived_7d_limit`
- `dynamic_cost_enabled`
- `enrichDynamicCostRuntime`
- `batchGetWindowCosts`

**Verification**:

```bash
grep WindowType backend/internal/service/account.go
grep computeEffectiveWindowCostLimit backend/internal/service/gateway_service.go
grep persistDerivedLimitsAndMilestones backend/internal/service/ratelimit_service.go
grep IsDynamicCostEnabled backend/internal/service/account.go
grep enrichDynamicCostRuntime backend/internal/handler/admin/account_handler.go
grep batchGetWindowCosts backend/internal/repository/session_limit_cache.go
grep dynamic_cost_enabled frontend/src/types/index.ts
go test -run "TestGetEffectiveWindowCostLimit|TestCheckWindowZone|TestManualLimitAccountsUnchanged" ./internal/service/
```

---

### Patch 20: Login Page Mobile Blur Performance Fix (added 2026-03-30)

**Status**: Active on main

**Purpose**: Disables GPU-intensive CSS blur effects on mobile devices to eliminate login page lag. Three `blur-3xl` gradient orbs (64px blur radius each) and a `backdrop-filter: blur(24px)` card cause expensive GPU compositing on low-power devices.

**Files**:

| File | Change |
|------|--------|
| `frontend/src/components/layout/AuthLayout.vue` | MODIFIED — added `auth-decorative-orbs` wrapper class, `auth-card` class on card div, scoped media query disabling blur on mobile |

**What changes on mobile** (`max-width: 768px` or `pointer: coarse`):
- Gradient orbs hidden (`display: none`) — eliminates three 64px blur compositing passes
- Card background switches from `backdrop-filter: blur(24px)` to opaque `rgba(255, 255, 255, 0.95)` (light) or `rgba(30, 41, 59, 0.95)` (dark)
- Grid pattern kept (cheap paint, no blur)

**Desktop unchanged**: glass blur effect fully preserved.

**Upstream conflict risk**: LOW — single file, scoped styles only.

**Reapply markers**:
- `auth-decorative-orbs`
- `auth-card`
- `pointer: coarse`

**Verification**:

```bash
grep auth-decorative-orbs frontend/src/components/layout/AuthLayout.vue
grep auth-card frontend/src/components/layout/AuthLayout.vue
grep "pointer: coarse" frontend/src/components/layout/AuthLayout.vue
```

---

## Verification

Run after every upstream merge to confirm patches survived:

```bash
# Patch 1: SUPERSEDED — no verification needed

# Patch 2: HTTP/2 upstream
grep '"h2"' backend/internal/pkg/tlsfingerprint/dialer.go
ls backend/internal/pkg/tlsfingerprint/h2_roundtripper.go

# Patch 3: Per-user quota
ls backend/internal/service/user_quota_service.go
ls backend/internal/repository/user_quota_cache.go
grep QuotaZoneGreen backend/internal/service/user_quota_service.go
grep zAddActivityScript backend/internal/repository/user_quota_cache.go
grep bumpEpochAndSetMetaScript backend/internal/repository/user_quota_cache.go
grep IsUserQuotaEnabled backend/internal/service/account.go
grep UserQuotaEnabled backend/internal/handler/dto/types.go
grep SetUserQuotaChecker backend/cmd/server/wire_gen.go
grep GetDisplayMetaBatch backend/internal/handler/admin/account_handler.go
grep NotifyAccountUpdated backend/internal/handler/admin/account_handler.go
grep showUserQuotaActive frontend/src/components/account/AccountCapacityCell.vue

# Patch 4: X25519MLKEM768 key shares
grep X25519MLKEM768 backend/internal/pkg/tlsfingerprint/dialer.go

# Patch 5: TLS profile cache key
grep profileKey backend/internal/pkg/tlsfingerprint/profile_identity.go

# Patch 6: Peak usage log
ls backend/internal/service/peak_usage_service.go
ls backend/internal/service/peak_usage_cache.go
ls backend/internal/repository/peak_usage_cache.go
ls backend/internal/handler/admin/peak_usage_handler.go
grep peakUpdateIfGreaterScript backend/internal/repository/peak_usage_cache.go
grep registerPeakUsageRoutes backend/internal/server/routes/admin.go
grep SetPeakUsageCache backend/internal/service/gateway_service.go

# Patch 7: Claude Code version detection
ls backend/internal/service/claude_code_version_detect_service.go

# Patch 8: CC Probe Service
ls backend/internal/service/cc_probe_service.go
grep cc-probe backend/internal/server/routes/admin.go

# Patch 9: Provider Routing
ls backend/internal/service/provider_routing.go
grep platformToProviders backend/internal/service/provider_routing.go
grep EnforceProviderRouting backend/internal/config/config.go
grep GetModelProvider backend/internal/service/pricing_service.go
grep isProviderAllowedForPlatform backend/internal/service/gateway_service.go

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

# Patch 13: InfoPopup tooltips
ls frontend/src/components/common/InfoPopup.vue
grep InfoPopup frontend/src/components/admin/usage/UsageTable.vue
grep InfoPopup frontend/src/views/user/UsageView.vue
grep floating-ui frontend/package.json
grep vue-demi frontend/vite.config.ts

# Patch 14: Scheduled Rate Multiplier
grep scheduled_rate_config backend/ent/schema/group.go
grep GetEffectiveRateMultiplier backend/internal/service/gateway_service.go
grep GetEffectiveRateMultiplier backend/internal/service/openai_gateway_service.go
grep ScheduledRateRulesEditor frontend/src/views/admin/GroupsView.vue
grep scheduledRate frontend/src/i18n/locales/en.ts | head -3

# Patch 15: Unified account test prompt
rg -n "SettingKeyAccountTestPrompt|legacyKeyProbePrompt|legacyKeyScheduledTestPrompt|GetAccountTestPrompt|account_test_prompt" backend frontend

# Patch 16: Local overload admission cooldown
rg -n "LocalOverloadTracker|SkipIfOverloaded|SettingKeyOverloadCooldownSettings|overload_cooldown_settings" backend frontend

# Patch 17: CSP nonce hardening
rg -n "NonceHTMLPlaceholder|replaceNoncePlaceholder|addNonceToScriptTags" backend/internal/web frontend/vite.config.ts

# Patch 18: Zero cache read pricing
grep ZeroCacheReadProviders backend/internal/config/config.go
grep applyCacheReadOverride backend/internal/service/billing_service.go

# Patch 19: Dynamic cost tracking
grep WindowType backend/internal/service/account.go
grep computeEffectiveWindowCostLimit backend/internal/service/gateway_service.go
grep persistDerivedLimitsAndMilestones backend/internal/service/ratelimit_service.go
grep batchGetWindowCosts backend/internal/repository/session_limit_cache.go
grep dynamic_cost_enabled frontend/src/types/index.ts

# Patch 20: Login page mobile blur fix
grep auth-decorative-orbs frontend/src/components/layout/AuthLayout.vue
grep auth-card frontend/src/components/layout/AuthLayout.vue
grep "pointer: coarse" frontend/src/components/layout/AuthLayout.vue

# utls version
grep refraction-networking/utls backend/go.mod
```

Check if utls has a new stable release:

```bash
curl -s https://api.github.com/repos/refraction-networking/utls/releases/latest | grep tag_name
```

## Notes

- **utls v1.8.2 pinned**: v1.8.2 has full X25519MLKEM768 support. Upgrade to a newer tagged release when available.
- **Baseline is content, not ancestry**: When reintroducing patches later, compare current upstream release content against this file. Do not rely on whether a historical fork commit still exists or whether upstream rewrote SHAs.
- **wire_gen.go is manually maintained**: Not generated by Wire. New dependencies are added by hand in `InitializeApp`. When resolving merge conflicts, keep upstream's `NewGatewayService` signature and fork's `userQuotaCache`/`userQuotaService` wiring.
- **Migration 074 checksum compatibility rule**: `migrations_runner.go` has a fork-specific compat entry for `074_add_group_scheduled_rate_config.sql`. Upstream v0.1.105 removed the DOWN section from this migration after the fork DB had already applied the original version. The rule accepts both the old and new checksums so the fork doesn't fail on startup. See `migrationChecksumCompatibilityRules` in `backend/internal/repository/migrations_runner.go`.
