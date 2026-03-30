<script setup lang="ts">
import { useI18n } from 'vue-i18n'
import InfoPopup from '@/components/common/InfoPopup.vue'
import type { UsageLog } from '@/types'

defineProps<{ row: UsageLog }>()
const { t } = useI18n()
</script>

<template>
  <InfoPopup>
    <div class="space-y-1.5">
      <div>
        <div class="text-xs font-semibold text-gray-300 mb-1">{{ t('usage.tokenDetails') }}</div>
        <div v-if="row.input_tokens > 0" class="flex items-center justify-between gap-4">
          <span class="text-gray-400">{{ t('admin.usage.inputTokens') }}</span>
          <span class="font-medium text-white">{{ row.input_tokens.toLocaleString() }}</span>
        </div>
        <div v-if="row.output_tokens > 0" class="flex items-center justify-between gap-4">
          <span class="text-gray-400">{{ t('admin.usage.outputTokens') }}</span>
          <span class="font-medium text-white">{{ row.output_tokens.toLocaleString() }}</span>
        </div>
        <div v-if="row.cache_creation_tokens > 0">
          <template v-if="row.cache_creation_5m_tokens > 0 || row.cache_creation_1h_tokens > 0">
            <div v-if="row.cache_creation_5m_tokens > 0" class="flex items-center justify-between gap-4">
              <span class="text-gray-400 flex items-center gap-1.5">{{ t('admin.usage.cacheCreation5mTokens') }}<span class="inline-flex items-center rounded px-1 py-px text-[10px] font-medium leading-tight bg-amber-500/20 text-amber-400 ring-1 ring-inset ring-amber-500/30">5m</span></span>
              <span class="font-medium text-white">{{ row.cache_creation_5m_tokens.toLocaleString() }}</span>
            </div>
            <div v-if="row.cache_creation_1h_tokens > 0" class="flex items-center justify-between gap-4">
              <span class="text-gray-400 flex items-center gap-1.5">{{ t('admin.usage.cacheCreation1hTokens') }}<span class="inline-flex items-center rounded px-1 py-px text-[10px] font-medium leading-tight bg-orange-500/20 text-orange-400 ring-1 ring-inset ring-orange-500/30">1h</span></span>
              <span class="font-medium text-white">{{ row.cache_creation_1h_tokens.toLocaleString() }}</span>
            </div>
          </template>
          <div v-else class="flex items-center justify-between gap-4">
            <span class="text-gray-400">{{ t('admin.usage.cacheCreationTokens') }}</span>
            <span class="font-medium text-white">{{ row.cache_creation_tokens.toLocaleString() }}</span>
          </div>
        </div>
        <div v-if="row.cache_ttl_overridden" class="flex items-center justify-between gap-4">
          <span class="text-gray-400 flex items-center gap-1.5">{{ t('usage.cacheTtlOverriddenLabel') }}<span class="inline-flex items-center rounded px-1 py-px text-[10px] font-medium leading-tight bg-rose-500/20 text-rose-400 ring-1 ring-inset ring-rose-500/30">R-{{ row.cache_creation_1h_tokens > 0 ? '5m' : '1H' }}</span></span>
          <span class="font-medium text-rose-400">{{ row.cache_creation_1h_tokens > 0 ? t('usage.cacheTtlOverridden1h') : t('usage.cacheTtlOverridden5m') }}</span>
        </div>
        <div v-if="row.cache_read_tokens > 0" class="flex items-center justify-between gap-4">
          <span class="text-gray-400">{{ t('admin.usage.cacheReadTokens') }}</span>
          <span class="font-medium text-white">{{ row.cache_read_tokens.toLocaleString() }}</span>
        </div>
      </div>
      <div class="flex items-center justify-between gap-6 border-t border-gray-700 pt-1.5">
        <span class="text-gray-400">{{ t('usage.totalTokens') }}</span>
        <span class="font-semibold text-blue-400">{{ ((row.input_tokens || 0) + (row.output_tokens || 0) + (row.cache_creation_tokens || 0) + (row.cache_read_tokens || 0)).toLocaleString() }}</span>
      </div>
    </div>
  </InfoPopup>
</template>
