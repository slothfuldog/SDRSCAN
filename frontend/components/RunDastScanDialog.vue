<script setup lang="ts">
import { friendlyError } from '~/utils/errors'
import { activeScanningAuthorized } from '~/utils/permissions'
import type { TargetLike } from '~/utils/permissions'
import { ACTIVE_SCAN_RUN_SUMMARY, ACTIVE_SCAN_TIMING_HELP, AUTHORIZE_ACTIVE_SCANNING_FIRST_HINT } from '~/utils/dastAuth'

// "Run scan" dialog for a DAST (URL) target: offers active (payload-sending) scanning only once it has
// been authorized separately in the codebase's settings (ActiveScanningSettings.vue); otherwise the
// toggle is disabled with a link there. A plain passive scan is always available.
const props = defineProps<{ open: boolean, codebase: TargetLike & { id: number, name: string } }>()
const emit = defineEmits<{ close: [], started: [scanId: number] }>()

const api = useApi()
const toast = useNotify()
const busy = ref(false)

const authorized = computed(() => activeScanningAuthorized(props.codebase))
const active = ref(false)
const activeTiming = ref(false)

watch(() => props.open, (o) => {
  if (!o) return
  active.value = false
  activeTiming.value = false
})
watch(active, (v) => { if (!v) activeTiming.value = false })

async function run() {
  if (busy.value) return
  busy.value = true
  try {
    const scan = await api.scans.create(props.codebase.id, { active: active.value, active_timing: activeTiming.value })
    emit('started', scan.id)
    await navigateTo(`/scans/${scan.id}`)
  } catch (e) {
    toast.error(friendlyError(e).message)
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <ModalDialog :open="open" title="Run DAST scan" :busy="busy" @close="emit('close')">
    <div class="space-y-4">
      <p class="text-muted">A passive scan reads the target only (headers, crawl, login) and never sends test payloads.</p>

      <div class="rounded-md border border-default p-3">
        <div class="flex items-start justify-between gap-3">
          <div>
            <p class="font-medium">Active scanning</p>
            <p class="text-xs text-muted">Sends SQL injection, XSS, open redirect and header-injection test payloads.</p>
          </div>
          <USwitch v-if="authorized" v-model="active" data-testid="active-scan-toggle" :disabled="busy" :aria-label="'Active scanning'" />
          <span v-else class="shrink-0 text-xs text-warning" data-testid="active-scan-disabled-hint">
            {{ AUTHORIZE_ACTIVE_SCANNING_FIRST_HINT }}
            <NuxtLink :to="`/codebases/${codebase.id}/settings#active-scanning`" class="text-primary underline-offset-2 hover:underline">Go to settings</NuxtLink>
          </span>
        </div>
        <div v-if="authorized && active" class="mt-3 border-t border-default pt-3">
          <div class="flex items-start justify-between gap-3">
            <div>
              <p class="text-sm font-medium">Time-based SQL injection tests (adds server load)</p>
              <p class="text-xs text-muted">{{ ACTIVE_SCAN_TIMING_HELP }}</p>
            </div>
            <USwitch v-model="activeTiming" data-testid="active-scan-timing-toggle" :disabled="busy" aria-label="Time-based SQL injection tests" />
          </div>
        </div>
      </div>

      <UAlert v-if="authorized && active" color="warning" variant="subtle" icon="i-lucide-triangle-alert" role="alert" data-testid="active-scan-summary" :description="ACTIVE_SCAN_RUN_SUMMARY" />
    </div>
    <template #footer>
      <UButton color="neutral" variant="outline" :disabled="busy" @click="emit('close')">Cancel</UButton>
      <UButton icon="i-lucide-play" :loading="busy" data-testid="confirm-run-scan" @click="run">{{ busy ? 'Starting…' : 'Run scan' }}</UButton>
    </template>
  </ModalDialog>
</template>
