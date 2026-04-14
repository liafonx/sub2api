# Active Fork Patches

This file lists the **11 patches currently applied** (3, 6, 9, 13, 18, 19, 20, 21, 22, 23, 24) to the `main` branch.
For full history and removed/superseded patches, see [FORK_CHANGELOG.md](FORK_CHANGELOG.md).

> **Baseline:** Merged upstream `v0.1.112` on 2026-04-13 (merge commit `b1052902`). All 10 patches re-verified and deployed to Mac Mini + VPS.

> **During upstream merges:** check each patch's key files for conflicts.
> See the `merge-upstream` skill for the full merge workflow.

---

## Patch 3 — Per-User Quota Allocation

**Purpose:** Split the global API quota equally among active users with a sticky reserve, and show a per-user quota badge in the UI.

**Upstream conflict risk:** HIGH — touches gateway, account service, and DTOs.

| Layer | Key Files |
|-------|-----------|
| Backend | `service/user_quota_service.go`, `repository/user_quota_cache.go`, `service/account.go`, `dto/types.go` |
| Handler | `handler/gateway_handler.go` |
| DI | `wire_gen.go` |
| Frontend | `components/layout/` (quota badge) |

**Verify:**
```bash
grep -r "UserQuota\|quota_badge\|sticky_reserve" backend/internal/
grep -r "quotaBadge\|userQuota" frontend/src/
```

---

## Patch 6 — Peak Usage Log

**Purpose:** Track and expose peak request-rate statistics; admin UI modal displays historical peak data.

**Upstream conflict risk:** MEDIUM — new service + handler, minimal overlap with upstream files.

| Layer | Key Files |
|-------|-----------|
| Backend | `service/peak_usage_service.go`, `service/peak_usage_cache.go`, `repository/peak_usage_cache.go` |
| Handler | `handler/admin/peak_usage_handler.go` |
| Frontend | (peak usage modal component) |

**Verify:**
```bash
grep -r "PeakUsage\|peak_usage" backend/internal/
grep -r "peakUsage\|PeakUsage" frontend/src/
```

---

## Patch 9 — Provider Routing

**Purpose:** Route requests to alternative providers based on pricing tiers and availability config.

**Upstream conflict risk:** HIGH — modifies gateway service and config loading.

| Layer | Key Files |
|-------|-----------|
| Backend | `service/provider_routing.go`, `service/pricing_service.go`, `service/gateway_service.go` |
| Config | `config/config.go` |

**Verify:**
```bash
grep -r "ProviderRouting\|provider_routing\|ProviderRoute" backend/internal/
grep "ProviderRouting\|RoutingConfig" backend/internal/config/config.go
```

---

## Patch 13 — InfoPopup Tooltip

**Purpose:** Reusable `InfoPopup.vue` tooltip component used in usage cost/token tables and views.

**Upstream conflict risk:** LOW — purely additive frontend component.

| Layer | Key Files |
|-------|-----------|
| Frontend | `components/common/InfoPopup.vue`, `components/UsageCostPopup.vue`, `components/UsageTokenPopup.vue` |
| Frontend | `views/UsageTable.vue`, `views/UsageView.vue`, `vite.config.ts` |

**Verify:**
```bash
grep -r "InfoPopup" frontend/src/
ls frontend/src/components/common/InfoPopup.vue
```

---

## Patch 18 — Zero Cache Read Pricing

**Purpose:** Treat cache-read tokens as zero-cost in billing calculations.

**Upstream conflict risk:** MEDIUM — modifies billing service and config; upstream may change billing logic.

| Layer | Key Files |
|-------|-----------|
| Config | `config/config.go` |
| Backend | `service/billing_service.go` |

**Verify:**
```bash
grep -n "cache_read\|CacheRead\|zeroCacheRead\|ZeroCacheRead" backend/internal/config/config.go backend/internal/service/billing_service.go
```

---

## Patch 19 — Dynamic Cost Tracking

**Purpose:** Track per-session costs dynamically; rate-limit and quota logic uses live cost data; admin UI shows cost modals.

**Upstream conflict risk:** HIGH — touches account service, gateway service, rate-limit service, session cache, and admin handler.

| Layer | Key Files |
|-------|-----------|
| Backend | `service/account.go`, `service/gateway_service.go`, `service/ratelimit_service.go` |
| Repository | `repository/session_limit_cache.go` |
| Handler | `handler/admin/account_handler.go` |
| Frontend | (cost modal components) |

**Verify:**
```bash
grep -rn "DynamicCost\|dynamic_cost\|SessionCost\|session_cost" backend/internal/
grep -r "costModal\|CostModal" frontend/src/
```

---

## Patch 20 — Login Page Mobile Blur Fix

**Purpose:** Disable CSS backdrop-filter blur on the login page for mobile browsers to fix rendering performance.

**Upstream conflict risk:** LOW — single frontend layout file.

| Layer | Key Files |
|-------|-----------|
| Frontend | `components/layout/AuthLayout.vue` |

**Verify:**
```bash
grep -n "blur\|backdrop" frontend/src/components/layout/AuthLayout.vue
```

---

## Patch 21 — User-Account Daily Affinity

**Purpose:** Pin each user to the same Anthropic account for the entire day. Affinity resets at a configurable UTC hour (default midnight). Backed by Redis with atomic Lua scripts; integrates as a super-sticky layer before session lookup; propagates `AffinityBound` to enable yellow quota zone access. Affinity-aware scoring spreads new users across accounts by preferring accounts with fewer existing bindings.

> **Bugfix 2026-04-13:** `APIKeyAuthGroupSnapshot` was missing `UserAccountAffinityEnabled`, making the feature a silent no-op since ship. Fixed in `api_key_auth_cache.go` and `api_key_auth_cache_impl.go`. After deploy, restart sub2api to flush stale cached snapshots.

**Upstream conflict risk:** HIGH — touches gateway_service, gateway_handler, ent schema, config, and admin DTOs.

| Layer | Key Files |
|-------|-----------|
| Backend | `service/user_affinity.go`, `repository/user_affinity_cache.go` |
| Gateway | `service/gateway_service.go` (`bindAffinityIfNeeded`, `filterByMinAffinityCount`, affinity-aware tiebreaker) |
| Gateway | `handler/gateway_handler*.go` |
| Schema | `ent/schema/group.go`, `migrations/082_add_group_user_account_affinity.sql` |
| Config | `config/config.go` (`affinity_reset_hour`) |
| Admin | `handler/admin/group_handler.go`, `handler/dto/types.go`, `handler/dto/mappers.go` |
| DI | `wire_gen.go` |
| Frontend | `views/admin/GroupsView.vue`, `types/index.ts`, `i18n/locales/` |
| Tests | `service/scheduler_layered_filter_test.go` (`TestFilterByMinAffinityCount`) |

**Verify:**
```bash
grep -rn "UserAffinity\|user_affinity\|AffinityBound\|AffinityReset" backend/internal/
grep -n "affinity_reset_hour" backend/internal/config/config.go
grep -n "user_account_affinity_enabled" frontend/src/views/admin/GroupsView.vue
grep -n "bindAffinityIfNeeded\|filterByMinAffinityCount" backend/internal/service/gateway_service.go
```

---

## Patch 22 — Per-User RPM Allocation

**Purpose:** Split an account's `base_rpm` equally among active users using the 3-zone (green/yellow/red) model. Counters auto-expire (120s TTL), limits computed on-the-fly as `baseRPM / activeCount`. Reuses the active-user sorted set from Patch 3.

**Upstream conflict risk:** HIGH — touches gateway handler, account service, user quota service, and DTOs.

| Layer | Key Files |
|-------|-----------|
| Backend | `service/user_quota_service.go`, `service/account.go`, `service/rpm_cache.go`, `repository/rpm_cache.go` |
| Handler | `handler/gateway_handler.go`, `service/gateway_service.go` |
| DI | `wire_gen.go` |
| DTO | `handler/dto/types.go` |
| Frontend | `components/account/EditAccountModal.vue`, `components/account/CreateAccountModal.vue`, `types/index.ts` |

**Verify:**
```bash
grep -rn "IsUserRPMEnabled\|user_rpm_enabled\|CheckUserRPM\|UserAccountRPM\|CheckRPMZone" backend/internal/
grep -rn "userRPMEnabled\|user_rpm_enabled" frontend/src/
```

---

## Patch 23 — Per-User RPM Cap

**Purpose:** Hard per-user RPM limit enforced at the gateway layer. New `rpm_limit` column on User (0 = unlimited). Configurable per-user via admin UI and globally via settings default (default 35 for new users). Pre-request check before concurrency slot acquisition; fail-open on Redis errors.

> **Note:** Git commits for this patch are tagged `fork-patch-21` (plan naming error — Patch 21 was already taken by Daily Affinity). The canonical patch number is 23.

**Upstream conflict risk:** HIGH — touches gateway handlers, ent schema, auth middleware, admin DTOs, and settings.

| Layer | Key Files |
|-------|-----------|
| Schema | `ent/schema/user.go`, DB migration: `ALTER TABLE users ADD COLUMN rpm_limit integer NOT NULL DEFAULT 0` |
| Backend | `service/user.go`, `service/rpm_cache.go`, `repository/rpm_cache.go`, `repository/user_repo.go`, `repository/api_key_repo.go` |
| Middleware | `server/middleware/auth_subject.go`, `api_key_auth.go`, `api_key_auth_google.go`, `jwt_auth.go`, `admin_auth.go` |
| Config | `config/config.go` (`user_rpm_limit` default 35), `service/domain_constants.go`, `service/setting_service.go`, `service/settings_view.go` |
| Handler | `handler/gateway_helper.go` (`checkUserRPMLimit`), `handler/gateway_handler.go`, `handler/gateway_handler_chat_completions.go`, `handler/gateway_handler_responses.go` |
| Handler | `handler/openai_gateway_handler.go`, `handler/openai_chat_completions.go` |
| Admin | `handler/admin/user_handler.go`, `handler/dto/types.go`, `handler/dto/mappers.go`, `service/admin_service.go` |
| DI | `wire_gen.go` |
| Frontend | `components/user/UserRPMCell.vue`, `components/admin/user/UserCreateModal.vue`, `components/admin/user/UserEditModal.vue` |
| Frontend | `views/admin/UsersView.vue`, `views/admin/SettingsView.vue`, `views/user/ProfileView.vue` |
| i18n | `i18n/locales/en.ts`, `i18n/locales/zh.ts` |

**Verify:**
```bash
grep -rn "RPMLimit\|rpm_limit\|checkUserRPMLimit\|GetUserRPM" backend/internal/
grep -rn "UserRPMCell\|rpmLimit\|rpm_limit" frontend/src/
```

---

## Patch 24 — Change Account Identity

**Purpose:** Add a "Change account" action to the admin More menu that swaps OAuth identity (credentials + name) on an existing account while preserving all settings. Frontend-only.

**Upstream conflict risk:** LOW — purely additive frontend component + minor wiring in AccountsView.

| Layer | Key Files |
|-------|-----------|
| Frontend | `components/admin/account/ChangeAccountModal.vue`, `components/admin/account/AccountActionMenu.vue` |
| Frontend | `views/admin/AccountsView.vue`, `i18n/locales/en.ts`, `i18n/locales/zh.ts` |

**Verify:**
```bash
grep -rn "ChangeAccountModal\|changeAccount\|change-account" frontend/src/
```

---

## Patches NOT on Main

Patches 1 (superseded), 2, 4, 5, 7, 8, 10, 11, 12, 14, 15, 16, 17 are **not present** on the current `main` branch.
Refer to [FORK_CHANGELOG.md](FORK_CHANGELOG.md) for their descriptions.
