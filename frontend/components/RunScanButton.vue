<script setup lang="ts">
import { friendlyError } from '~/utils/errors'
import { runScanState } from '~/utils/permissions'
import type { TargetLike } from '~/utils/permissions'

// "Run scan": visible/enabled per role and target state (a convenience only: the server decides).
// A scan started from the web is always a full scan. SAST runs immediately; DAST opens a dialog
// (RunDastScanDialog) that also offers active scanning once it has been authorized. On success we
// move to the Scan run page.
const props = defineProps<{ codebase: TargetLike & { id: number, name: string }, small?: boolean, disabledExtra?: boolean }>()
const emit = defineEmits<{ started: [scanId: number] }>()

const auth = useAuth()
const api = useApi()
const toast = useNotify()
const busy = ref(false)
const dialogOpen = ref(false)

const state = computed(() => runScanState(auth.user, props.codebase))
const isDast = computed(() => props.codebase.target_type === 'url')
const hintId = `run-hint-${useId()}`

async function started(scanId: number) {
  dialogOpen.value = false
  emit('started', scanId)
}

async function run() {
  if (busy.value || !state.value.enabled) return
  if (isDast.value) { dialogOpen.value = true; return }
  busy.value = true
  try {
    const scan = await api.scans.create(props.codebase.id)
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
  <span v-if="state.visible" class="inline-flex flex-col items-start gap-1">
    <UButton
      icon="i-lucide-play" :size="small ? 'xs' : 'md'" :disabled="!state.enabled || busy || disabledExtra" :loading="busy"
      :aria-describedby="state.reason ? hintId : undefined" data-testid="run-scan" @click="run"
    >{{ busy ? 'Starting…' : 'Run scan' }}</UButton>
    <span v-if="state.reason" :id="hintId" class="max-w-56 whitespace-normal text-left text-xs text-warning">{{ state.reason }}</span>
    <RunDastScanDialog v-if="isDast" :open="dialogOpen" :codebase="codebase" @close="dialogOpen = false" @started="started" />
  </span>
</template>
