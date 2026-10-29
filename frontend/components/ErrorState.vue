<script setup lang="ts">
import { friendlyError } from '~/utils/errors'

// Friendly rendering for 401/403/404/409/network errors, with "Try again" when it makes sense.
// `notFoundMessage` lets a page word its own 404 (for example "Codebase not found.").
const props = defineProps<{ error: unknown, notFoundMessage?: string }>()
const emit = defineEmits<{ retry: [] }>()

const info = computed(() => {
  const f = friendlyError(props.error)
  return f.kind === 'not_found' && props.notFoundMessage ? { ...f, message: props.notFoundMessage } : f
})
const actions = computed(() => {
  const list: Array<Record<string, unknown>> = []
  if (info.value.retryable) list.push({ label: 'Try again', icon: 'i-lucide-refresh-cw', color: 'neutral', variant: 'outline', size: 'xs', onClick: () => emit('retry') })
  if (info.value.kind === 'not_found' || info.value.kind === 'forbidden') list.push({ label: 'Back to Projects', to: '/', color: 'neutral', variant: 'outline', size: 'xs' })
  return list
})
</script>

<template>
  <UAlert color="error" variant="subtle" icon="i-lucide-circle-alert" :title="info.title" :description="info.message" :actions="actions as never" role="alert" data-testid="error-state" />
</template>
