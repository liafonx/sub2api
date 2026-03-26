<template>
  <BaseDialog
    :show="show"
    :title="entityType === 'account' ? t('peakUsage.titleAccounts') : t('peakUsage.titleUsers')"
    width="wide"
    @close="emit('close')"
  >
    <!-- Loading State -->
    <div v-if="loading" class="flex items-center justify-center py-12">
      <LoadingSpinner />
    </div>

    <!-- Empty State -->
    <div
      v-else-if="entries.length === 0"
      class="flex flex-col items-center justify-center py-12 text-gray-500 dark:text-gray-400"
    >
      <p class="text-sm">{{ t('peakUsage.noData') }}</p>
    </div>

    <!-- Entry Grid -->
    <div v-else class="grid grid-cols-1 gap-3 sm:grid-cols-2">
      <div
        v-for="entry in entries"
        :key="entry.entity_id"
        class="card p-4"
      >
        <!-- Card Header -->
        <div class="mb-3 flex items-start justify-between">
          <div>
            <template v-if="entityType === 'user'">
              <p class="font-bold text-gray-900 dark:text-gray-100">{{ entry.entity_label }}</p>
            </template>
            <template v-else>
              <p class="font-semibold text-gray-900 dark:text-gray-100">{{ entry.entity_name }}</p>
              <p v-if="entry.entity_label" class="text-xs text-gray-500 dark:text-gray-400">
                {{ entry.entity_label }}
              </p>
            </template>
          </div>
        </div>

        <!-- Tracking Since -->
        <p v-if="entry.reset_at" class="mb-2 text-xs text-gray-400 dark:text-gray-500">
          {{ t('peakUsage.trackingSince') }}: {{ new Date(entry.reset_at).toLocaleString() }}
        </p>

        <!-- Metric Rows -->
        <div class="space-y-2">
          <!-- Concurrency -->
          <div class="flex items-center justify-between">
            <span class="text-xs font-medium uppercase tracking-wide text-gray-500 dark:text-gray-400">
              {{ t('peakUsage.concurrency') }}
            </span>
            <span class="text-sm font-bold text-blue-600 dark:text-blue-400">
              <template v-if="entry.max_concurrency">
                {{ entry.peak_concurrency }} / {{ entry.max_concurrency }}
              </template>
              <template v-else>
                {{ entry.peak_concurrency }}
              </template>
            </span>
          </div>

          <!-- Sessions -->
          <div class="flex items-center justify-between">
            <span class="text-xs font-medium uppercase tracking-wide text-gray-500 dark:text-gray-400">
              {{ t('peakUsage.sessions') }}
            </span>
            <span class="text-sm font-bold text-teal-600 dark:text-teal-400">
              <template v-if="entry.max_sessions">
                {{ entry.peak_sessions }} / {{ entry.max_sessions }}
              </template>
              <template v-else>
                {{ entry.peak_sessions }}
              </template>
            </span>
          </div>

          <!-- RPM -->
          <div class="flex items-center justify-between">
            <span class="text-xs font-medium uppercase tracking-wide text-gray-500 dark:text-gray-400">
              {{ t('peakUsage.rpm') }}
            </span>
            <span class="text-sm font-bold text-purple-600 dark:text-purple-400">
              <template v-if="entry.max_rpm">
                {{ entry.peak_rpm }} / {{ entry.max_rpm }}
              </template>
              <template v-else>
                {{ entry.peak_rpm }}
              </template>
            </span>
          </div>
        </div>
      </div>
    </div>

    <!-- Footer -->
    <template #footer>
      <div class="flex items-center justify-end">
        <button
          @click="showConfirmReset = true"
          class="rounded-lg bg-red-600 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-red-700 focus:outline-none focus:ring-2 focus:ring-red-500 focus:ring-offset-2 dark:focus:ring-offset-dark-800"
        >
          {{ t('peakUsage.resetAll') }}
        </button>
      </div>
    </template>
  </BaseDialog>

  <!-- Reset Confirmation Dialog -->
  <ConfirmDialog
    :show="showConfirmReset"
    :title="t('peakUsage.resetConfirmTitle')"
    :message="t('peakUsage.resetConfirmMessage')"
    :confirm-text="t('peakUsage.resetConfirmBtn')"
    :danger="true"
    @confirm="handleReset"
    @cancel="showConfirmReset = false"
  />
</template>

<script setup lang="ts">
import { ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { adminAPI } from '@/api/admin'
import { useAppStore } from '@/stores/app'
import type { PeakUsageEntry } from '@/types'
import BaseDialog from '@/components/common/BaseDialog.vue'
import ConfirmDialog from '@/components/common/ConfirmDialog.vue'
import LoadingSpinner from '@/components/common/LoadingSpinner.vue'

const props = defineProps<{
  show: boolean
  entityType: 'account' | 'user'
}>()

const emit = defineEmits<{ (e: 'close'): void }>()

const { t } = useI18n()
const appStore = useAppStore()

const loading = ref(false)
const entries = ref<PeakUsageEntry[]>([])
const showConfirmReset = ref(false)

watch(
  () => props.show,
  async (val) => {
    if (val) await fetchData()
  }
)

async function fetchData() {
  loading.value = true
  try {
    const fn =
      props.entityType === 'account'
        ? adminAPI.peakUsage.getAccountPeaks
        : adminAPI.peakUsage.getUserPeaks
    entries.value = (await fn()) ?? []
  } catch {
    appStore.showError(t('peakUsage.fetchError'))
  } finally {
    loading.value = false
  }
}

async function handleReset() {
  showConfirmReset.value = false
  try {
    await adminAPI.peakUsage.resetPeaks(props.entityType)
    appStore.showSuccess(t('peakUsage.resetSuccess'))
    await fetchData()
  } catch {
    appStore.showError(t('peakUsage.resetError'))
  }
}
</script>
