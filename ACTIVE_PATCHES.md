# Active Fork Patches

This file is the **single source of truth** for all fork-only patches on `main`.
Currently **11 active patches** (3, 6, 9, 13, 18, 19, 20, 21, 22, 23, 24).

> **Baseline:** Merged upstream `v0.1.113` on 2026-04-16 (merge commit `fe5f7dd3`).

> **During upstream merges:** check each patch's key files for conflicts.
> See the `merge-upstream` skill for the full merge workflow.

---

## Patch 3 — Per-User Quota Allocation

**Purpose:** Split the global API quota equally among active users with a sticky reserve, and show a per-user quota badge in the UI.

**Upstream conflict risk:** HIGH — touches gateway, account service, and DTOs.

| Layer | Key Files |
|-------|-----------|
| Backend | `service/user_quota_service.go`, `repository/user_quota_cache.go`, `service/account.go`, `dto/types.go` |
| Gateway | `service/gateway_service.go` (`SetUserQuotaChecker`, `CheckUserQuotaForAccount`, `RegisterUserActivity`, `IncrementUserCost`) |
| Handler | `handler/gateway_handler.go`, `handler/admin/account_handler.go` (`GetDisplayMetaBatch`, `NotifyAccountUpdated`) |
| DTO | `handler/dto/mappers.go` |
| DI | `wire_gen.go` |
| Frontend | `components/account/AccountCapacityCell.vue` (quota badge) |

---

## Patch 6 — Peak Usage Log

**Purpose:** Track all-time peak values for concurrency, sessions, and RPM per account/user. Redis stores live peaks; 5-minute flush persists to Postgres. Admin UI shows peaks with reset capability.

**Upstream conflict risk:** MEDIUM — new service + handler, minimal overlap with upstream files.

| Layer | Key Files |
|-------|-----------|
| Backend | `service/peak_usage_service.go`, `service/peak_usage_cache.go`, `repository/peak_usage_cache.go` |
| Backend | `service/concurrency_service.go` (concurrency peak recording), `service/gateway_service.go` (`SetPeakUsageCache`, sessions/RPM peak tracking) |
| Schema | `ent/schema/peak_usage.go` |
| Routes | `server/routes/admin.go` (`registerPeakUsageRoutes`) |
| Handler | `handler/admin/peak_usage_handler.go` |
| Frontend | `components/admin/PeakUsageModal.vue`, `views/admin/DashboardView.vue` (mounts `PeakUsageModal`) |

---

## Patch 9 — Provider Routing

**Purpose:** Optionally rejects requests where the model's `litellm_provider` doesn't match the account's platform (e.g. prevents OpenAI models routing to Anthropic accounts). Off by default (`enforce_provider_routing: false`).

**Upstream conflict risk:** LOW — small inline check + new file; `gateway_service.go` hook is a single conditional.

| Layer | Key Files |
|-------|-----------|
| Backend | `service/provider_routing.go`, `service/pricing_service.go`, `service/gateway_service.go` |
| Config | `config/config.go` |

---

## Patch 13 — InfoPopup Tooltip

**Purpose:** Reusable `InfoPopup.vue` tooltip component used in usage cost/token tables and views.

**Upstream conflict risk:** LOW — purely additive frontend component.

| Layer | Key Files |
|-------|-----------|
| Frontend | `components/common/InfoPopup.vue`, `components/common/UsageCostPopup.vue`, `components/common/UsageTokenPopup.vue` |
| Frontend | `components/admin/usage/UsageTable.vue`, `views/user/UsageView.vue`, `vite.config.ts` |

---

## Patch 18 — Zero Cache Read Pricing

**Purpose:** Zero out cache-read token pricing for configurable providers (e.g. Anthropic doesn't charge for cache reads, but LiteLLM lists a non-zero rate).

**Upstream conflict risk:** LOW — two new functions + minor change to `GetModelPricing` return statements.

| Layer | Key Files |
|-------|-----------|
| Config | `config/config.go` (`zero_cache_read_providers`) |
| Backend | `service/billing_service.go` (`applyCacheReadOverride`, `inferProviderFromModelName`) |

---

## Patch 19 — Dynamic Cost Tracking

**Purpose:** Auto-derive 5h and 7d dollar limits from Anthropic utilization headers instead of manual thresholds. Graduated-trust algorithm: high utilization (>=5%) trusts `cost/utilization`; low utilization caps by fallback; very low uses fallback only.

**Upstream conflict risk:** MEDIUM — touches `gateway_service.go`, `ratelimit_service.go`, `account_handler.go`, `wire_gen.go`.

| Layer | Key Files |
|-------|-----------|
| Backend | `service/account.go`, `service/gateway_service.go`, `service/ratelimit_service.go` |
| Repository | `repository/session_limit_cache.go` |
| Handler | `handler/admin/account_handler.go` |
| DTO | `handler/dto/types.go`, `handler/dto/mappers.go` |
| DI | `wire_gen.go` |
| Frontend | `components/account/CreateAccountModal.vue`, `components/account/EditAccountModal.vue` |

---

## Patch 20 — Login Page Mobile Blur Fix

**Purpose:** Disable CSS backdrop-filter blur on the login page for mobile browsers to fix rendering performance.

**Upstream conflict risk:** LOW — single frontend layout file.

| Layer | Key Files |
|-------|-----------|
| Frontend | `components/layout/AuthLayout.vue` |

---

## Patch 21 — User-Account Daily Affinity

**Purpose:** Pin each user to the same Anthropic account for the entire day. Affinity resets at a configurable UTC hour (default midnight). Backed by Redis with atomic Lua scripts; integrates as a super-sticky layer before session lookup; propagates `AffinityBound` to enable yellow quota zone access. Affinity-aware scoring spreads new users across accounts by preferring accounts with fewer existing bindings.

**Merge gotchas:** `APIKeyAuthGroupSnapshot` must include `UserAccountAffinityEnabled` (auth cache). `buildSchedulerMetadataAccount` must include `GroupIDs` (scheduler metadata cache). Both were silent no-ops when missing.

**Upstream conflict risk:** HIGH — touches gateway_service, gateway_handler, ent schema, config, and admin DTOs.

| Layer | Key Files |
|-------|-----------|
| Backend | `service/user_affinity.go`, `repository/user_affinity_cache.go` |
| Auth Cache | `service/api_key_auth_cache.go` (`APIKeyAuthGroupSnapshot` struct — must include `UserAccountAffinityEnabled`) |
| Auth Cache | `service/api_key_auth_cache_impl.go` (populates `UserAccountAffinityEnabled` from group settings) |
| Scheduler | `repository/scheduler_cache.go` (`buildSchedulerMetadataAccount` — must include `GroupIDs`) |
| Gateway | `service/gateway_service.go` (`bindAffinityIfNeeded`, `filterByMinAffinityCount`, affinity-aware tiebreaker) |
| Gateway | `handler/gateway_handler*.go` |
| Schema | `ent/schema/group.go`, `migrations/082_add_group_user_account_affinity.sql` |
| Config | `config/config.go` (`affinity_reset_hour`) |
| Admin | `handler/admin/group_handler.go`, `handler/dto/types.go`, `handler/dto/mappers.go` |
| DI | `wire_gen.go` |
| Frontend | `views/admin/GroupsView.vue`, `types/index.ts`, `i18n/locales/` |
| Tests | `service/scheduler_layered_filter_test.go` (`TestFilterByMinAffinityCount`) |

---

## Patch 22 — Per-User RPM Allocation

**Purpose:** Split an account's `base_rpm` equally among active users using the 3-zone (green/yellow/red) model. Counters auto-expire (120s TTL), limits computed on-the-fly as `baseRPM / activeCount`. Reuses the active-user sorted set from Patch 3.

**Upstream conflict risk:** HIGH — touches gateway handler, account service, user quota service, and DTOs.

| Layer | Key Files |
|-------|-----------|
| Backend | `service/user_quota_service.go`, `service/account.go`, `service/rpm_cache.go`, `repository/rpm_cache.go` |
| Handler | `handler/gateway_handler.go`, `handler/gateway_handler_chat_completions.go`, `handler/gateway_handler_responses.go`, `service/gateway_service.go` |
| DI | `wire_gen.go` |
| DTO | `handler/dto/types.go` |
| Frontend | `components/account/EditAccountModal.vue`, `components/account/CreateAccountModal.vue`, `types/index.ts` |

---

## Patch 23 — Per-User RPM Cap

**Purpose:** Hard per-user RPM limit enforced at the gateway layer. New `rpm_limit` column on User (0 = unlimited). Configurable per-user via admin UI and globally via settings default (default 35 for new users). Pre-request check before concurrency slot acquisition; fail-open on Redis errors.

**Upstream conflict risk:** HIGH — touches gateway handlers, ent schema, auth middleware, admin DTOs, and settings.

| Layer | Key Files |
|-------|-----------|
| Schema | `ent/schema/user.go`, migration `103_add_user_rpm_limit.sql` |
| Backend | `service/user.go`, `service/auth_service.go` (applies `GetDefaultRPMLimit` on new user creation), `service/rpm_cache.go`, `repository/rpm_cache.go`, `repository/user_repo.go`, `repository/api_key_repo.go` |
| Middleware | `server/middleware/auth_subject.go`, `api_key_auth.go`, `api_key_auth_google.go`, `jwt_auth.go`, `admin_auth.go` |
| Config | `config/config.go` (`user_rpm_limit` default 35), `service/domain_constants.go`, `service/setting_service.go`, `service/settings_view.go` |
| Handler | `handler/gateway_helper.go` (`checkUserRPMLimit`), `handler/gateway_handler.go`, `handler/gateway_handler_chat_completions.go`, `handler/gateway_handler_responses.go` |
| Handler | `handler/openai_gateway_handler.go`, `handler/openai_chat_completions.go` |
| Admin | `handler/admin/user_handler.go`, `handler/dto/types.go`, `handler/dto/mappers.go`, `service/admin_service.go` |
| DI | `wire_gen.go` |
| Frontend | `components/user/UserRPMCell.vue`, `components/admin/user/UserCreateModal.vue`, `components/admin/user/UserEditModal.vue` |
| Frontend | `views/admin/UsersView.vue`, `views/admin/SettingsView.vue`, `views/user/ProfileView.vue` |
| i18n | `i18n/locales/en.ts`, `i18n/locales/zh.ts` |

---

## Patch 24 — Change Account Identity

**Purpose:** Add a "Change account" action to the admin More menu that swaps auth identity (credentials + name) on an existing account while preserving all settings. Frontend-only.

**Upstream conflict risk:** LOW — purely additive frontend component + minor wiring in AccountsView.

| Layer | Key Files |
|-------|-----------|
| Frontend | `components/admin/account/ChangeAccountModal.vue`, `components/admin/account/AccountActionMenu.vue` |
| Frontend | `views/admin/AccountsView.vue`, `i18n/locales/en.ts`, `i18n/locales/zh.ts` |

---

## Verification

Run after every upstream merge to confirm all patches survived:

```bash
# Patch 3: Per-user quota
grep QuotaZoneGreen backend/internal/service/user_quota_service.go
grep IsUserQuotaEnabled backend/internal/service/account.go
grep SetUserQuotaChecker backend/cmd/server/wire_gen.go

# Patch 6: Peak usage log
ls backend/internal/service/peak_usage_service.go
grep peakUpdateIfGreaterScript backend/internal/repository/peak_usage_cache.go
grep registerPeakUsageRoutes backend/internal/server/routes/admin.go

# Patch 9: Provider Routing
grep platformToProviders backend/internal/service/provider_routing.go
grep EnforceProviderRouting backend/internal/config/config.go
grep isProviderAllowedForPlatform backend/internal/service/gateway_service.go

# Patch 13: InfoPopup tooltips
ls frontend/src/components/common/InfoPopup.vue
grep UsageCostPopup frontend/src/components/admin/usage/UsageTable.vue
grep floating-ui frontend/package.json

# Patch 18: Zero cache read pricing
grep ZeroCacheReadProviders backend/internal/config/config.go
grep applyCacheReadOverride backend/internal/service/billing_service.go

# Patch 19: Dynamic cost tracking
grep computeEffectiveWindowCostLimit backend/internal/service/gateway_service.go
grep persistDerivedLimitsAndMilestones backend/internal/service/ratelimit_service.go
grep dynamic_cost_enabled frontend/src/types/index.ts

# Patch 20: Login page mobile blur fix
grep auth-decorative-orbs frontend/src/components/layout/AuthLayout.vue
grep "pointer: coarse" frontend/src/components/layout/AuthLayout.vue

# Patch 21: User-account daily affinity
grep -n bindAffinityIfNeeded backend/internal/service/gateway_service.go
grep -n filterByMinAffinityCount backend/internal/service/gateway_service.go
grep -n user_account_affinity_enabled backend/ent/schema/group.go
grep -n FieldUserAccountAffinityEnabled backend/internal/repository/api_key_repo.go
grep -n GroupIDs backend/internal/repository/scheduler_cache.go

# Patch 22: Per-user RPM allocation
grep -n IsUserRPMEnabled backend/internal/service/account.go
grep -n CheckUserRPM backend/internal/service/user_quota_service.go

# Patch 23: Per-user RPM cap
grep -n checkUserRPMLimit backend/internal/handler/gateway_helper.go
grep -n rpm_limit backend/ent/schema/user.go

# Patch 24: Change account identity
ls frontend/src/components/admin/account/ChangeAccountModal.vue
grep -n change-account frontend/src/components/admin/account/AccountActionMenu.vue
```

---

## Notes

- **wire_gen.go is manually maintained**: Not generated by Wire. New dependencies are added by hand in `InitializeApp`.
- **Retired patches** (1-2, 4-5, 7-8, 10-12, 14-17): superseded or archived. Code preserved on branch `archive/fork-main-pre-clean-migration-2026-03-28` and matching tag.
