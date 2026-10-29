<script setup lang="ts">
import { friendlyError } from '~/utils/errors'
import { isActive } from '~/utils/scanStream'
import type { ActiveScan } from '~/types/api'

// Compact live status of a queued/running scan on the Codebase page (SSE with polling fallback).
const props = defineProps<{ scan: ActiveScan }>()
const emit = defineEmits<{ finished: [] }>()

const api = useApi()
const toast = useNotify()
const { scan: live, lines } = useScanEvents(() => props.scan.id, { onFinished: () => emit('finished') })
const status = computed(() => live.value?.status ?? props.scan.status)
const lastLine = computed(() => lines.value[lines.value.length - 1] ?? '')
const cancelling = ref(false)

async function cancel() {
  cancelling.value = true
  try {
    await api.scans.cancel(props.scan.id)
    toast.info('Cancellation requested.')
  } catch (e) {
    toast.error(friendlyError(e).message)
  } finally {
    cancelling.value = false
  }
}
</script>

<template>
  <UAlert color="info" variant="subtle" data-testid="active-scan" role="status">
    <template #description>
      <div class="flex flex-wrap items-center gap-3">
        <ScanStatusBadge :status="status" />
        <span class="font-medium">Scan #{{ scan.id }}</span>
        <span class="min-w-0 flex-1 truncate font-mono text-xs text-muted">{{ lastLine }}</span>
        <ULink :to="`/scans/${scan.id}`" class="text-primary underline-offset-2 hover:underline">View run</ULink>
        <UButton v-if="isActive(status)" color="neutral" variant="outline" size="xs" icon="i-lucide-square" :loading="cancelling" @click="cancel">Cancel</UButton>
      </div>
    </template>
  </UAlert>
</template>
