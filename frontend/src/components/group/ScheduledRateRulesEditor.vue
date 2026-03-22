<template>
  <div class="rounded-lg border border-gray-200 p-2 sm:p-4 dark:border-dark-600">
    <!-- Enable toggle header -->
    <div class="flex items-center justify-between">
      <div>
        <label class="input-label mb-0">{{ t('admin.groups.scheduledRate.title') }}</label>
        <p class="mt-1 text-xs text-gray-500 dark:text-gray-400">
          {{ t('admin.groups.scheduledRate.hint') }}
        </p>
      </div>
      <Toggle
        :model-value="config.enabled"
        @update:model-value="updateConfig({ enabled: $event })"
      />
    </div>

    <!-- Rules editor (visible when enabled) -->
    <div v-if="config.enabled" class="mt-4 space-y-3">
      <!-- Hint texts -->
      <div class="space-y-1">
        <p class="text-xs text-gray-500 dark:text-gray-400">
          {{ t('admin.groups.scheduledRate.timezoneWarning', { timezone: serverTimezone }) }}
        </p>
        <p class="text-xs text-gray-500 dark:text-gray-400">
          {{ t('admin.groups.scheduledRate.firstMatchHint') }}
        </p>
      </div>

      <!-- No rules placeholder -->
      <div
        v-if="config.rules.length === 0"
        class="py-6 text-center text-sm text-gray-400 dark:text-gray-500"
      >
        {{ t('admin.groups.scheduledRate.noRules') }}
      </div>

      <!-- Rule cards -->
      <div
        v-for="(rule, index) in config.rules"
        :key="index"
        class="rounded-lg border border-gray-200 p-2 sm:p-4 dark:border-dark-600"
      >
        <!-- Rule header -->
        <div class="mb-3 flex items-center justify-between">
          <span class="text-sm font-medium text-gray-700 dark:text-gray-300">
            {{ t('admin.groups.scheduledRate.ruleSummary', { index: index + 1 }) }}
          </span>
          <div class="flex items-center gap-1">
            <!-- Move up -->
            <button
              v-if="index > 0"
              type="button"
              :title="t('admin.groups.scheduledRate.moveUp')"
              class="rounded p-1 text-gray-400 transition-colors hover:bg-gray-100 hover:text-gray-600 dark:hover:bg-dark-600 dark:hover:text-gray-300"
              @click="moveRule(index, -1)"
            >
              <svg class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                <path stroke-linecap="round" stroke-linejoin="round" d="M5 15l7-7 7 7" />
              </svg>
            </button>
            <!-- Move down -->
            <button
              v-if="index < config.rules.length - 1"
              type="button"
              :title="t('admin.groups.scheduledRate.moveDown')"
              class="rounded p-1 text-gray-400 transition-colors hover:bg-gray-100 hover:text-gray-600 dark:hover:bg-dark-600 dark:hover:text-gray-300"
              @click="moveRule(index, 1)"
            >
              <svg class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                <path stroke-linecap="round" stroke-linejoin="round" d="M19 9l-7 7-7-7" />
              </svg>
            </button>
            <!-- Remove -->
            <button
              type="button"
              :title="t('admin.groups.scheduledRate.removeRule')"
              class="rounded p-1 text-gray-400 transition-colors hover:bg-red-50 hover:text-red-600 dark:hover:bg-red-900/20 dark:hover:text-red-400"
              @click="removeRule(index)"
            >
              <svg class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                <path stroke-linecap="round" stroke-linejoin="round" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
              </svg>
            </button>
          </div>
        </div>

        <!-- Rule fields grid -->
        <div class="space-y-4">
          <!-- Rate multiplier -->
          <div>
            <label class="text-sm font-medium text-gray-700 dark:text-gray-300">
              {{ t('admin.groups.scheduledRate.rateMultiplier') }}
            </label>
            <input
              type="number"
              step="0.001"
              min="0"
              :value="rule.rate_multiplier"
              class="input mt-2 block max-w-[200px]"
              @change="updateRule(index, { rate_multiplier: parseFloat(($event.target as HTMLInputElement).value) || 1.0 })"
            />
          </div>

          <!-- Days of week -->
          <div>
            <label class="text-sm font-medium text-gray-700 dark:text-gray-300">
              {{ t('admin.groups.scheduledRate.days') }}
            </label>
            <div class="mt-1.5 space-y-2">
              <!-- Day checkboxes -->
              <div class="flex flex-wrap gap-2">
                <label
                  v-for="dayIndex in dayDisplayOrder"
                  :key="dayIndex"
                  class="flex cursor-pointer items-center gap-1.5 text-sm"
                >
                  <input
                    type="checkbox"
                    :checked="(rule.days ?? []).includes(dayIndex)"
                    class="rounded border-gray-300 text-primary-600 focus:ring-primary-500 dark:border-dark-500"
                    @change="toggleDay(index, dayIndex, ($event.target as HTMLInputElement).checked)"
                  />
                  <span class="text-gray-700 dark:text-gray-300">{{ dayNames[dayIndex] }}</span>
                </label>
              </div>
              <!-- Quick select buttons -->
              <div class="flex gap-2">
                <button
                  type="button"
                  class="rounded border border-gray-200 px-2 py-0.5 text-xs text-gray-600 transition-colors hover:bg-gray-50 dark:border-dark-500 dark:text-gray-400 dark:hover:bg-dark-600"
                  @click="setDays(index, [1, 2, 3, 4, 5])"
                >
                  {{ t('admin.groups.scheduledRate.weekdays') }}
                </button>
                <button
                  type="button"
                  class="rounded border border-gray-200 px-2 py-0.5 text-xs text-gray-600 transition-colors hover:bg-gray-50 dark:border-dark-500 dark:text-gray-400 dark:hover:bg-dark-600"
                  @click="setDays(index, [0, 6])"
                >
                  {{ t('admin.groups.scheduledRate.weekend') }}
                </button>
                <button
                  type="button"
                  class="rounded border border-gray-200 px-2 py-0.5 text-xs text-gray-600 transition-colors hover:bg-gray-50 dark:border-dark-500 dark:text-gray-400 dark:hover:bg-dark-600"
                  @click="setDays(index, [0, 1, 2, 3, 4, 5, 6])"
                >
                  {{ t('admin.groups.scheduledRate.allDays') }}
                </button>
              </div>
            </div>
          </div>

          <!-- Time window -->
          <div>
            <label class="text-sm font-medium text-gray-700 dark:text-gray-300">
              {{ t('admin.groups.scheduledRate.timeWindow') }}
            </label>
            <div class="mt-1.5 space-y-2">
              <div>
                <span class="text-xs text-gray-500 dark:text-gray-400">
                  {{ t('admin.groups.scheduledRate.timeStart') }}
                </span>
                <input
                  type="time"
                  :value="rule.time_start ?? ''"
                  class="input mt-1 w-full min-w-0"
                  @change="updateRule(index, { time_start: ($event.target as HTMLInputElement).value || undefined })"
                />
              </div>
              <div>
                <span class="text-xs text-gray-500 dark:text-gray-400">
                  {{ t('admin.groups.scheduledRate.timeEnd') }}
                </span>
                <input
                  type="time"
                  :value="rule.time_end ?? ''"
                  class="input mt-1 w-full min-w-0"
                  @change="updateRule(index, { time_end: ($event.target as HTMLInputElement).value || undefined })"
                />
              </div>
              <!-- Time mode radios -->
              <div class="flex flex-wrap gap-x-4 gap-y-1">
                <label class="flex cursor-pointer items-center gap-1.5 text-sm">
                  <input
                    type="radio"
                    :checked="(rule.time_mode ?? 'include') === 'include'"
                    class="text-primary-600 focus:ring-primary-500"
                    @change="updateRule(index, { time_mode: 'include' })"
                  />
                  <span class="text-gray-700 dark:text-gray-300">
                    {{ t('admin.groups.scheduledRate.timeModeInclude') }}
                  </span>
                </label>
                <label class="flex cursor-pointer items-center gap-1.5 text-sm">
                  <input
                    type="radio"
                    :checked="(rule.time_mode ?? 'include') === 'exclude'"
                    class="text-primary-600 focus:ring-primary-500"
                    @change="updateRule(index, { time_mode: 'exclude' })"
                  />
                  <span class="text-gray-700 dark:text-gray-300">
                    {{ t('admin.groups.scheduledRate.timeModeExclude') }}
                  </span>
                </label>
              </div>
            </div>
          </div>

          <!-- Date range -->
          <div>
            <label class="text-sm font-medium text-gray-700 dark:text-gray-300">
              {{ t('admin.groups.scheduledRate.dateRange') }}
            </label>
            <div class="mt-1.5 space-y-2">
              <div>
                <span class="text-xs text-gray-500 dark:text-gray-400">
                  {{ t('admin.groups.scheduledRate.dateStart') }}
                </span>
                <input
                  type="date"
                  :value="rule.date_start ?? ''"
                  class="input mt-1 w-full min-w-0"
                  @change="updateRule(index, { date_start: ($event.target as HTMLInputElement).value || undefined })"
                />
              </div>
              <div>
                <span class="text-xs text-gray-500 dark:text-gray-400">
                  {{ t('admin.groups.scheduledRate.dateEnd') }}
                </span>
                <input
                  type="date"
                  :value="rule.date_end ?? ''"
                  class="input mt-1 w-full min-w-0"
                  @change="updateRule(index, { date_end: ($event.target as HTMLInputElement).value || undefined })"
                />
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- Add rule / max rules hint -->
      <div class="flex items-center gap-3">
        <button
          type="button"
          :disabled="config.rules.length >= MAX_RULES"
          class="rounded border border-primary-500 px-3 py-1.5 text-sm text-primary-600 transition-colors hover:bg-primary-50 dark:border-primary-400 dark:text-primary-400 dark:hover:bg-primary-900/20 disabled:cursor-not-allowed disabled:opacity-50"
          @click="addRule"
        >
          {{ t('admin.groups.scheduledRate.addRule') }}
        </button>
        <span
          v-if="config.rules.length >= MAX_RULES"
          class="text-xs text-gray-500 dark:text-gray-400"
        >
          {{ t('admin.groups.scheduledRate.maxRulesReached') }}
        </span>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import type { ScheduledRateConfig, ScheduledRateRule } from '@/types'
import Toggle from '@/components/common/Toggle.vue'

const MAX_RULES = 10

const props = defineProps<{
  modelValue: ScheduledRateConfig | null
  serverTimezone: string
}>()

const emit = defineEmits<{
  'update:modelValue': [value: ScheduledRateConfig | null]
}>()

const { t } = useI18n()

// Mon(1)…Sat(6), Sun(0) — display order, indices match backend convention (0=Sun)
const dayDisplayOrder = [1, 2, 3, 4, 5, 6, 0]

const dayNames = computed(() => [
  t('admin.groups.scheduledRate.daySun'),
  t('admin.groups.scheduledRate.dayMon'),
  t('admin.groups.scheduledRate.dayTue'),
  t('admin.groups.scheduledRate.dayWed'),
  t('admin.groups.scheduledRate.dayThu'),
  t('admin.groups.scheduledRate.dayFri'),
  t('admin.groups.scheduledRate.daySat'),
])

const config = computed<ScheduledRateConfig>(() => props.modelValue ?? { enabled: false, rules: [] })

function updateConfig(update: Partial<ScheduledRateConfig>) {
  emit('update:modelValue', { ...config.value, ...update })
}

function updateRule(index: number, update: Partial<ScheduledRateRule>) {
  const newRules = config.value.rules.map((r, i) => i === index ? { ...r, ...update } : r)
  updateConfig({ rules: newRules })
}

function addRule() {
  if (config.value.rules.length >= MAX_RULES) return
  const newRule: ScheduledRateRule = { rate_multiplier: 1.0 }
  updateConfig({ rules: [...config.value.rules, newRule] })
}

function removeRule(index: number) {
  updateConfig({ rules: config.value.rules.filter((_, i) => i !== index) })
}

function moveRule(index: number, direction: -1 | 1) {
  const rules = [...config.value.rules]
  const target = index + direction
  if (target < 0 || target >= rules.length) return
  ;[rules[index], rules[target]] = [rules[target], rules[index]]
  updateConfig({ rules })
}

function setDays(index: number, days: number[]) {
  updateRule(index, { days })
}

function toggleDay(index: number, day: number, checked: boolean) {
  const current = config.value.rules[index].days ?? []
  const newDays = checked
    ? [...current, day].sort((a, b) => a - b)
    : current.filter(d => d !== day)
  updateRule(index, { days: newDays.length > 0 ? newDays : undefined })
}
</script>
