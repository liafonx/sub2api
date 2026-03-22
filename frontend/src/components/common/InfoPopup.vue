<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { useFloating, flip, shift, offset, arrow, autoUpdate } from '@floating-ui/vue'

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

function toggle() {
  open.value = !open.value
}

function show() {
  open.value = true
}

function hide() {
  open.value = false
}

function handleClickOutside(event: MouseEvent) {
  if (!open.value) return
  const target = event.target as Node
  if (referenceEl.value?.contains(target) || floatingEl.value?.contains(target)) return
  open.value = false
}

onMounted(() => document.addEventListener('click', handleClickOutside, true))
onUnmounted(() => document.removeEventListener('click', handleClickOutside, true))
</script>

<template>
  <span ref="referenceEl" data-trigger class="inline-flex" @click="toggle" @pointerenter="e => e.pointerType === 'mouse' && show()" @pointerleave="e => e.pointerType === 'mouse' && hide()">
    <slot name="trigger" />
  </span>

  <Teleport to="body">
    <div
      v-if="open"
      ref="floatingEl"
      data-floating
      class="z-[9999] pointer-events-none"
      :style="floatingStyles"
    >
      <div class="whitespace-nowrap rounded-lg border border-gray-700 bg-gray-900 px-3 py-2.5 text-xs text-white shadow-xl dark:border-gray-600 dark:bg-gray-800">
        <slot />
        <!-- Dynamic arrow triangle -->
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
