<template>
  <div class="flex flex-col gap-1.5">
    <!-- 并发槽位 -->
    <div class="flex items-center gap-1.5">
      <span
        :class="[
          'inline-flex items-center gap-1 rounded-md px-2 py-0.5 text-xs font-medium',
          concurrencyClass
        ]"
      >
        <svg class="h-3 w-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
          <path stroke-linecap="round" stroke-linejoin="round" d="M3.75 6A2.25 2.25 0 016 3.75h2.25A2.25 2.25 0 0110.5 6v2.25a2.25 2.25 0 01-2.25 2.25H6a2.25 2.25 0 01-2.25-2.25V6zM3.75 15.75A2.25 2.25 0 016 13.5h2.25a2.25 2.25 0 012.25 2.25V18a2.25 2.25 0 01-2.25 2.25H6A2.25 2.25 0 013.75 18v-2.25zM13.5 6a2.25 2.25 0 012.25-2.25H18A2.25 2.25 0 0120.25 6v2.25A2.25 2.25 0 0118 10.5h-2.25a2.25 2.25 0 01-2.25-2.25V6zM13.5 15.75a2.25 2.25 0 012.25-2.25H18a2.25 2.25 0 012.25 2.25V18A2.25 2.25 0 0118 20.25h-2.25A2.25 2.25 0 0113.5 18v-2.25z" />
        </svg>
        <span class="font-mono">{{ currentConcurrency }}</span>
        <span class="text-gray-400 dark:text-gray-500">/</span>
        <span class="font-mono">{{ account.concurrency }}</span>
      </span>
    </div>

    <!-- 5h窗口费用限制（仅 Anthropic OAuth/SetupToken 且启用时显示） -->
    <div v-if="showWindowCost" class="flex items-center gap-1">
      <span
        :class="[
          'inline-flex items-center gap-1 rounded-md px-1.5 py-0.5 text-[10px] font-medium',
          windowCostClass
        ]"
        :title="windowCostTooltip"
      >
        <svg class="h-2.5 w-2.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
          <path stroke-linecap="round" stroke-linejoin="round" d="M12 6v12m-3-2.818l.879.659c1.171.879 3.07.879 4.242 0 1.172-.879 1.172-2.303 0-3.182C13.536 12.219 12.768 12 12 12c-.725 0-1.45-.22-2.003-.659-1.106-.879-1.106-2.303 0-3.182s2.9-.879 4.006 0l.415.33M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
        <span class="font-mono">${{ formatCost(currentWindowCost) }}</span>
        <span class="text-gray-400 dark:text-gray-500">/</span>
        <span class="font-mono">${{ formatCost(effective5hLimit) }}</span>
      </span>
    </div>

    <!-- 每用户配额（仅 user_quota_enabled 时显示） -->
    <div v-if="showUserQuotaActive || showUserQuotaIdle" class="flex items-center gap-1">
      <span
        :class="[
          'inline-flex items-center gap-1 rounded-md px-1.5 py-0.5 text-[10px] font-medium',
          showUserQuotaActive
            ? 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400'
            : 'bg-gray-100 text-gray-500 dark:bg-gray-800 dark:text-gray-400'
        ]"
        :title="showUserQuotaActive
          ? t('admin.accounts.capacity.userQuota.active', { count: activeUserCount, limit: formatCost(perUserLimit) })
          : t('admin.accounts.capacity.userQuota.inactive')"
      >
        <svg class="h-2.5 w-2.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
          <path stroke-linecap="round" stroke-linejoin="round" d="M18 18.72a9.094 9.094 0 003.741-.479 3 3 0 00-4.682-2.72m.94 3.198l.001.031c0 .225-.012.447-.037.666A11.944 11.944 0 0112 21c-2.17 0-4.207-.576-5.963-1.584A6.062 6.062 0 016 18.719m12 0a5.971 5.971 0 00-.941-3.197m0 0A5.995 5.995 0 0012 12.75a5.995 5.995 0 00-5.058 2.772m0 0a3 3 0 00-4.681 2.72 8.986 8.986 0 003.74.477m.94-3.197a5.971 5.971 0 00-.94 3.197M15 6.75a3 3 0 11-6 0 3 3 0 016 0zm6 3a2.25 2.25 0 11-4.5 0 2.25 2.25 0 014.5 0zm-13.5 0a2.25 2.25 0 11-4.5 0 2.25 2.25 0 014.5 0z" />
        </svg>
        <template v-if="showUserQuotaActive">
          <span class="font-mono">{{ activeUserCount }}</span>
          <span class="text-gray-400 dark:text-gray-500">&middot;</span>
          <span class="font-mono">${{ formatCost(perUserLimit) }}</span>
        </template>
        <span v-else class="font-mono">Q</span>
      </span>
    </div>

    <!-- 会话数量限制（仅 Anthropic OAuth/SetupToken 且启用时显示） -->
    <div v-if="showSessionLimit" class="flex items-center gap-1">
      <span
        :class="[
          'inline-flex items-center gap-1 rounded-md px-1.5 py-0.5 text-[10px] font-medium',
          sessionLimitClass
        ]"
        :title="sessionLimitTooltip"
      >
        <svg class="h-2.5 w-2.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
          <path stroke-linecap="round" stroke-linejoin="round" d="M15 19.128a9.38 9.38 0 002.625.372 9.337 9.337 0 004.121-.952 4.125 4.125 0 00-7.533-2.493M15 19.128v-.003c0-1.113-.285-2.16-.786-3.07M15 19.128v.106A12.318 12.318 0 018.624 21c-2.331 0-4.512-.645-6.374-1.766l-.001-.109a6.375 6.375 0 0111.964-3.07M12 6.375a3.375 3.375 0 11-6.75 0 3.375 3.375 0 016.75 0zm8.25 2.25a2.625 2.625 0 11-5.25 0 2.625 2.625 0 015.25 0z" />
        </svg>
        <span class="font-mono">{{ activeSessions }}</span>
        <span class="text-gray-400 dark:text-gray-500">/</span>
        <span class="font-mono">{{ account.max_sessions }}</span>
      </span>
    </div>

    <!-- RPM 限制（仅 Anthropic OAuth/SetupToken 且启用时显示） -->
    <div v-if="showRpmLimit" class="flex items-center gap-1">
      <span
        :class="[
          'inline-flex items-center gap-1 rounded-md px-1.5 py-0.5 text-[10px] font-medium',
          rpmClass
        ]"
        :title="rpmTooltip"
      >
        <svg class="h-2.5 w-2.5" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor">
          <path stroke-linecap="round" stroke-linejoin="round" d="M12 6v6h4.5m4.5 0a9 9 0 1 1-18 0 9 9 0 0 1 18 0Z" />
        </svg>
        <span class="font-mono">{{ currentRPM }}</span>
        <span class="text-gray-400 dark:text-gray-500">/</span>
        <span class="font-mono">{{ account.base_rpm }}</span>
        <span class="text-[9px] opacity-60">{{ rpmStrategyTag }}</span>
      </span>
    </div>

    <!-- API Key 账号配额限制 -->
    <QuotaBadge v-if="showDailyQuota" :used="account.quota_daily_used ?? 0" :limit="account.quota_daily_limit!" label="D" />
    <QuotaBadge v-if="showWeeklyQuota" :used="account.quota_weekly_used ?? 0" :limit="account.quota_weekly_limit!" label="W" />
    <QuotaBadge v-if="showTotalQuota" :used="account.quota_used ?? 0" :limit="account.quota_limit!" />
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import type { Account } from '@/types'
import QuotaBadge from './QuotaBadge.vue'

const props = defineProps<{
  account: Account
}>()

const { t } = useI18n()

// 当前并发数
const currentConcurrency = computed(() => props.account.current_concurrency || 0)

// 是否为 Anthropic OAuth/SetupToken 账号
const isAnthropicOAuthOrSetupToken = computed(() => {
  return (
    props.account.platform === 'anthropic' &&
    (props.account.type === 'oauth' || props.account.type === 'setup-token')
  )
})

// Effective 5h limit: prefer derived, fall back to manual
const effective5hLimit = computed(() => {
  return props.account.effective_5h_limit ?? props.account.window_cost_limit ?? 0
})

// 是否显示窗口费用限制
const showWindowCost = computed(() => {
  return isAnthropicOAuthOrSetupToken.value && effective5hLimit.value > 0
})

// 当前窗口费用
const currentWindowCost = computed(() => props.account.current_window_cost ?? 0)

// 每用户配额 — compute from real-time cost data when available to avoid stale cache lag
const activeUserCount = computed(() => props.account.active_user_count ?? 0)
const perUserLimit = computed(() => {
  // When we have real-time cost + effective limit + active users, compute directly
  if (
    effective5hLimit.value > 0 &&
    activeUserCount.value > 0 &&
    props.account.current_window_cost != null
  ) {
    const remaining = Math.max(0, effective5hLimit.value - currentWindowCost.value)
    return remaining / activeUserCount.value
  }
  // Fall back to cached backend value
  return props.account.per_user_limit ?? 0
})

const showUserQuotaActive = computed(() => {
  return (
    props.account.user_quota_enabled === true &&
    props.account.per_user_limit != null &&
    activeUserCount.value > 0
  )
})

const showUserQuotaIdle = computed(() => {
  return (
    props.account.user_quota_enabled === true &&
    !showUserQuotaActive.value
  )
})

// 是否显示会话限制
const showSessionLimit = computed(() => {
  return (
    isAnthropicOAuthOrSetupToken.value &&
    props.account.max_sessions !== undefined &&
    props.account.max_sessions !== null &&
    props.account.max_sessions > 0
  )
})

// 当前活跃会话数
const activeSessions = computed(() => props.account.active_sessions ?? 0)

// 并发状态样式
const concurrencyClass = computed(() => {
  const current = currentConcurrency.value
  const max = props.account.concurrency

  if (current >= max) {
    return 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400'
  }
  if (current > 0) {
    return 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400'
  }
  return 'bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-400'
})

// 窗口费用状态样式
const windowCostClass = computed(() => {
  if (!showWindowCost.value) return ''

  const current = currentWindowCost.value
  const limit = effective5hLimit.value
  const reserve = props.account.window_cost_sticky_reserve || 10

  if (current >= limit + reserve) {
    return 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400'
  }
  if (current >= limit) {
    return 'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-400'
  }
  if (current >= limit * 0.8) {
    return 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400'
  }
  return 'bg-emerald-100 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-400'
})

// 窗口费用提示文字
const windowCostTooltip = computed(() => {
  if (!showWindowCost.value) return ''

  const current = currentWindowCost.value
  const limit = effective5hLimit.value
  const reserve = props.account.window_cost_sticky_reserve || 10

  if (current >= limit + reserve) {
    return t('admin.accounts.capacity.windowCost.blocked')
  }
  if (current >= limit) {
    return t('admin.accounts.capacity.windowCost.stickyOnly')
  }
  return t('admin.accounts.capacity.windowCost.normal')
})

// 会话限制状态样式
const sessionLimitClass = computed(() => {
  if (!showSessionLimit.value) return ''

  const current = activeSessions.value
  const max = props.account.max_sessions || 0

  if (current >= max) {
    return 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400'
  }
  if (current >= max * 0.8) {
    return 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400'
  }
  return 'bg-emerald-100 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-400'
})

// 会话限制提示文字
const sessionLimitTooltip = computed(() => {
  if (!showSessionLimit.value) return ''

  const current = activeSessions.value
  const max = props.account.max_sessions || 0
  const idle = props.account.session_idle_timeout_minutes || 5

  if (current >= max) {
    return t('admin.accounts.capacity.sessions.full', { idle })
  }
  return t('admin.accounts.capacity.sessions.normal', { idle })
})

// 是否显示 RPM 限制
const showRpmLimit = computed(() => {
  return (
    isAnthropicOAuthOrSetupToken.value &&
    props.account.base_rpm !== undefined &&
    props.account.base_rpm !== null &&
    props.account.base_rpm > 0
  )
})

// 当前 RPM 计数
const currentRPM = computed(() => props.account.current_rpm ?? 0)

// RPM 策略
const rpmStrategy = computed(() => props.account.rpm_strategy || 'tiered')

// RPM 策略标签
const rpmStrategyTag = computed(() => {
  return rpmStrategy.value === 'sticky_exempt' ? '[S]' : '[T]'
})

// RPM buffer 计算（与后端一致：base <= 0 时 buffer 为 0）
const rpmBuffer = computed(() => {
  const base = props.account.base_rpm || 0
  return props.account.rpm_sticky_buffer ?? (base > 0 ? Math.max(1, Math.floor(base / 5)) : 0)
})

// RPM 状态样式
const rpmClass = computed(() => {
  if (!showRpmLimit.value) return ''

  const current = currentRPM.value
  const base = props.account.base_rpm ?? 0
  const buffer = rpmBuffer.value

  if (rpmStrategy.value === 'tiered') {
    if (current >= base + buffer) {
      return 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400'
    }
    if (current >= base) {
      return 'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-400'
    }
  } else {
    if (current >= base) {
      return 'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-400'
    }
  }
  if (current >= base * 0.8) {
    return 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400'
  }
  return 'bg-emerald-100 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-400'
})

// RPM 提示文字（增强版：显示策略、区域、缓冲区）
const rpmTooltip = computed(() => {
  if (!showRpmLimit.value) return ''

  const current = currentRPM.value
  const base = props.account.base_rpm ?? 0
  const buffer = rpmBuffer.value

  if (rpmStrategy.value === 'tiered') {
    if (current >= base + buffer) {
      return t('admin.accounts.capacity.rpm.tieredBlocked', { buffer })
    }
    if (current >= base) {
      return t('admin.accounts.capacity.rpm.tieredStickyOnly', { buffer })
    }
    if (current >= base * 0.8) {
      return t('admin.accounts.capacity.rpm.tieredWarning')
    }
    return t('admin.accounts.capacity.rpm.tieredNormal')
  } else {
    if (current >= base) {
      return t('admin.accounts.capacity.rpm.stickyExemptOver')
    }
    if (current >= base * 0.8) {
      return t('admin.accounts.capacity.rpm.stickyExemptWarning')
    }
    return t('admin.accounts.capacity.rpm.stickyExemptNormal')
  }
})

// 是否显示各维度配额（apikey / bedrock 类型）
const isQuotaEligible = computed(() => props.account.type === 'apikey' || props.account.type === 'bedrock')

const showDailyQuota = computed(() => {
  return isQuotaEligible.value && (props.account.quota_daily_limit ?? 0) > 0
})

const showWeeklyQuota = computed(() => {
  return isQuotaEligible.value && (props.account.quota_weekly_limit ?? 0) > 0
})

const showTotalQuota = computed(() => {
  return isQuotaEligible.value && (props.account.quota_limit ?? 0) > 0
})

// 格式化费用显示
const formatCost = (value: number | null | undefined) => {
  if (value === null || value === undefined) return '0'
  return value.toFixed(2)
}
</script>
