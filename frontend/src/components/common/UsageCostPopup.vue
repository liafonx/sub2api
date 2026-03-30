<script setup lang="ts">
import { useI18n } from 'vue-i18n'
import { formatTokenPricePerMillion } from '@/utils/usagePricing'
import { getUsageServiceTierLabel } from '@/utils/usageServiceTier'
import InfoPopup from '@/components/common/InfoPopup.vue'
import type { UsageLog } from '@/types'

defineProps<{
  row: UsageLog & { account_rate_multiplier?: number | null }
  showAccountBilling?: boolean
}>()
const { t } = useI18n()
</script>

<template>
  <InfoPopup>
    <div class="space-y-1.5">
      <div class="mb-2 border-b border-gray-700 pb-1.5">
        <div class="text-xs font-semibold text-gray-300 mb-1">{{ t('usage.costDetails') }}</div>
        <div v-if="row.input_cost > 0" class="flex items-center justify-between gap-4">
          <span class="text-gray-400">{{ t('admin.usage.inputCost') }}</span>
          <span class="font-medium text-white">${{ row.input_cost.toFixed(6) }}</span>
        </div>
        <div v-if="row.output_cost > 0" class="flex items-center justify-between gap-4">
          <span class="text-gray-400">{{ t('admin.usage.outputCost') }}</span>
          <span class="font-medium text-white">${{ row.output_cost.toFixed(6) }}</span>
        </div>
        <div v-if="row.input_tokens > 0" class="flex items-center justify-between gap-4">
          <span class="text-gray-400">{{ t('usage.inputTokenPrice') }}</span>
          <span class="font-medium text-sky-300">{{ formatTokenPricePerMillion(row.input_cost, row.input_tokens) }} {{ t('usage.perMillionTokens') }}</span>
        </div>
        <div v-if="row.output_tokens > 0" class="flex items-center justify-between gap-4">
          <span class="text-gray-400">{{ t('usage.outputTokenPrice') }}</span>
          <span class="font-medium text-violet-300">{{ formatTokenPricePerMillion(row.output_cost, row.output_tokens) }} {{ t('usage.perMillionTokens') }}</span>
        </div>
        <div v-if="row.cache_creation_cost > 0" class="flex items-center justify-between gap-4">
          <span class="text-gray-400">{{ t('admin.usage.cacheCreationCost') }}</span>
          <span class="font-medium text-white">${{ row.cache_creation_cost.toFixed(6) }}</span>
        </div>
        <div v-if="row.cache_read_cost > 0" class="flex items-center justify-between gap-4">
          <span class="text-gray-400">{{ t('admin.usage.cacheReadCost') }}</span>
          <span class="font-medium text-white">${{ row.cache_read_cost.toFixed(6) }}</span>
        </div>
      </div>
      <div class="flex items-center justify-between gap-6">
        <span class="text-gray-400">{{ t('usage.serviceTier') }}</span>
        <span class="font-semibold text-cyan-300">{{ getUsageServiceTierLabel(row.service_tier, t) }}</span>
      </div>
      <div class="flex items-center justify-between gap-6">
        <span class="text-gray-400">{{ t('usage.rate') }}</span>
        <span class="font-semibold text-blue-400">{{ (row.rate_multiplier || 1).toFixed(2) }}x</span>
      </div>
      <template v-if="showAccountBilling">
        <div class="flex items-center justify-between gap-6">
          <span class="text-gray-400">{{ t('usage.accountMultiplier') }}</span>
          <span class="font-semibold text-blue-400">{{ (row.account_rate_multiplier ?? 1).toFixed(2) }}x</span>
        </div>
        <div class="flex items-center justify-between gap-6">
          <span class="text-gray-400">{{ t('usage.original') }}</span>
          <span class="font-medium text-white">${{ row.total_cost?.toFixed(6) || '0.000000' }}</span>
        </div>
        <div class="flex items-center justify-between gap-6">
          <span class="text-gray-400">{{ t('usage.userBilled') }}</span>
          <span class="font-semibold text-green-400">${{ row.actual_cost?.toFixed(6) || '0.000000' }}</span>
        </div>
        <div class="flex items-center justify-between gap-6 border-t border-gray-700 pt-1.5">
          <span class="text-gray-400">{{ t('usage.accountBilled') }}</span>
          <span class="font-semibold text-green-400">${{ (((row.total_cost || 0) * (row.account_rate_multiplier ?? 1)) || 0).toFixed(6) }}</span>
        </div>
      </template>
      <template v-else>
        <div class="flex items-center justify-between gap-6">
          <span class="text-gray-400">{{ t('usage.original') }}</span>
          <span class="font-medium text-white">${{ row.total_cost?.toFixed(6) || '0.000000' }}</span>
        </div>
        <div class="flex items-center justify-between gap-6 border-t border-gray-700 pt-1.5">
          <span class="text-gray-400">{{ t('usage.billed') }}</span>
          <span class="font-semibold text-green-400">${{ row.actual_cost?.toFixed(6) || '0.000000' }}</span>
        </div>
      </template>
    </div>
  </InfoPopup>
</template>
