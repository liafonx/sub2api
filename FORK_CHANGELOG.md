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

**Purpose**: Detects Claude Code client versions from request headers for per-version routing or analytics.

**Files**: `backend/internal/service/claude_code_detect_service.go`

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
ls backend/internal/service/claude_code_detect_service.go

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
