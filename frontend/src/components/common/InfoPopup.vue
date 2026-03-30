<script lang="ts">
// Module-level singleton: truly shared across all instances.
// Declared here (not in <script setup>) so it runs once at module scope,
// not once per component instance inside setup().
let closeActivePopup: (() => void) | null = null
let activeContains: ((t: Node) => boolean) | null = null
let listenerCount = 0

function handleGlobalClick(event: MouseEvent) {
  if (!closeActivePopup) return
  const target = event.target as Node
  if (activeContains?.(target)) return
  // If clicking another InfoPopup trigger, let its toggle() handle closing this one
  const el = target instanceof Element ? target : target.parentElement
  if (el?.closest('[data-infopopup-trigger]')) return
  closeActivePopup()
}
</script>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { useFloating, flip, shift, offset, arrow, autoUpdate } from '@floating-ui/vue'
import Icon from '@/components/icons/Icon.vue'

const open = ref(false)
const referenceEl = ref<HTMLElement | null>(null)
const floatingEl = ref<HTMLElement | null>(null)
const arrowEl = ref<HTMLElement | null>(null)

const { floatingStyles, placement, middlewareData } = useFloating(referenceEl, floatingEl, {
  placement: 'right',
  middleware: [offset(8), flip(), shift({ padding: 8 }), arrow({ element: arrowEl })],
  whileElementsMounted: autoUpdate,
})

// Which side the arrow lives on (opposite of popup placement)
const arrowSide = computed<'left' | 'right' | 'top' | 'bottom'>(() => {
  const base = placement.value.split('-')[0] as 'right' | 'left' | 'top' | 'bottom'
  const sides = { right: 'left', left: 'right', top: 'bottom', bottom: 'top' } as const
  return sides[base]
})

const arrowStyle = computed(() => {
  const { x, y } = middlewareData.value.arrow ?? {}
  return {
    left: x != null ? `${x}px` : '',
    top: y != null ? `${y}px` : '',
    [arrowSide.value]: '-4px',
    position: 'absolute' as const,
  }
})

function hide() {
  open.value = false
  if (closeActivePopup === hide) {
    closeActivePopup = null
    activeContains = null
  }
}

function show() {
  if (open.value) return
  closeActivePopup?.()
  open.value = true
  closeActivePopup = hide
  // Capture refs via closure so floatingEl resolves after v-if renders
  activeContains = (t: Node) =>
    (referenceEl.value?.contains(t) ?? false) || (floatingEl.value?.contains(t) ?? false)
}

function toggle() {
  if (open.value) {
    hide()
  } else {
    show()
  }
}

onMounted(() => {
  if (listenerCount === 0) document.addEventListener('click', handleGlobalClick, true)
  listenerCount++
})
onUnmounted(() => {
  listenerCount--
  if (listenerCount === 0) document.removeEventListener('click', handleGlobalClick, true)
  if (closeActivePopup === hide) {
    closeActivePopup = null
    activeContains = null
  }
})
</script>

<template>
  <span ref="referenceEl" data-infopopup-trigger class="inline-flex" @click="toggle" @pointerenter="e => e.pointerType === 'mouse' && show()" @pointerleave="e => e.pointerType === 'mouse' && hide()">
    <slot name="trigger">
      <div class="flex h-4 w-4 cursor-help items-center justify-center rounded-full bg-gray-100 transition-colors hover:bg-blue-100 dark:bg-gray-700 dark:hover:bg-blue-900/50">
        <Icon name="infoCircle" size="xs" class="text-gray-400 hover:text-blue-500 dark:text-gray-500 dark:hover:text-blue-400" />
      </div>
    </slot>
  </span>

  <Teleport to="body">
    <div
      v-if="open"
      ref="floatingEl"
      data-floating
      class="z-[9999] pointer-events-none"
      :style="floatingStyles"
    >
      <div class="pointer-events-auto whitespace-nowrap rounded-lg border border-gray-700 bg-gray-900 px-3 py-2.5 text-xs text-white shadow-xl dark:border-gray-600 dark:bg-gray-800">
        <slot />
        <div
          ref="arrowEl"
          :style="arrowStyle"
          class="h-0 w-0"
          :class="{
            'border-t-[6px] border-b-[6px] border-r-[6px] border-t-transparent border-b-transparent border-r-gray-900 dark:border-r-gray-800': arrowSide === 'left',
            'border-t-[6px] border-b-[6px] border-l-[6px] border-t-transparent border-b-transparent border-l-gray-900 dark:border-l-gray-800': arrowSide === 'right',
            'border-l-[6px] border-r-[6px] border-b-[6px] border-l-transparent border-r-transparent border-b-gray-900 dark:border-b-gray-800': arrowSide === 'top',
            'border-l-[6px] border-r-[6px] border-t-[6px] border-l-transparent border-r-transparent border-t-gray-900 dark:border-t-gray-800': arrowSide === 'bottom',
          }"
        />
      </div>
    </div>
  </Teleport>
</template>
