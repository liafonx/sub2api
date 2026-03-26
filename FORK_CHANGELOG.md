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
