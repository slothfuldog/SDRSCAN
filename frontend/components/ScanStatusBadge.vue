<script setup lang="ts">
import { STATUS_LABEL } from '~/utils/scanStream'
import type { ScanStatus } from '~/types/api'

defineProps<{ status: ScanStatus }>()
const COLOR: Record<ScanStatus, 'neutral' | 'info' | 'success' | 'error'> = { queued: 'neutral', running: 'info', succeeded: 'success', failed: 'error', cancelled: 'neutral' }
const ICON: Record<ScanStatus, string> = {
  queued: 'i-lucide-clock', running: 'i-lucide-refresh-cw', succeeded: 'i-lucide-check', failed: 'i-lucide-x', cancelled: 'i-lucide-square',
}
</script>

<template>
  <UBadge :color="COLOR[status]" variant="subtle" size="sm" :icon="ICON[status]" :ui="{ leadingIcon: status === 'running' ? 'motion-safe:animate-spin' : '' }" data-testid="scan-status">
    {{ STATUS_LABEL[status] }}
  </UBadge>
</template>
