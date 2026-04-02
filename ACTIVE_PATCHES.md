# Active Fork Patches

This file lists the **7 patches currently applied** to the `main` branch.
For full history and removed/superseded patches, see [FORK_CHANGELOG.md](FORK_CHANGELOG.md).

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

## Patches NOT on Main

Patches 1 (superseded), 2, 4, 5, 7, 8, 10, 11, 12, 14, 15, 16, 17 are **not present** on the current `main` branch.
Refer to [FORK_CHANGELOG.md](FORK_CHANGELOG.md) for their descriptions.
