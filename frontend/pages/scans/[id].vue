<script setup lang="ts">
import { friendlyError } from '~/utils/errors'
import { formatDuration } from '~/utils/format'
import { isActive, isTerminal, scanErrorText } from '~/utils/scanStream'
import { scanActiveInfo, scanAuthInfo } from '~/utils/dastAuth'

const api = useApi()
const route = useRoute()
const toast = useNotify()
const id = computed(() => Number(route.params.id))

const { scan, lines, error, transport, restart } = useScanEvents(id)
const { data: codebase, reload: loadCodebase } = useLoad(async () => (scan.value ? api.codebases.get(scan.value.codebase_id) : undefined), { watch: [() => scan.value?.codebase_id], immediate: false })
useHead(() => ({ title: `Scan #${id.value} · SDRScan` }))

// DAST runs: the job log tells whether the scan logged in and how many pages the crawl fetched (never a credential).
const authInfo = computed(() => (scan.value?.type === 'dast' ? scanAuthInfo(lines.value) : null))
// Active (payload-sending) scanning: the scan row carries the flags; the log carries who authorized it and the request count.
const activeInfo = computed(() => (scan.value?.type === 'dast' ? scanActiveInfo(lines.value) : null))

const logEl = ref<HTMLElement | null>(null)
watch(() => lines.value.length, async () => {
  await nextTick()
  if (logEl.value) logEl.value.scrollTop = logEl.value.scrollHeight
})
watch(() => scan.value?.status, (s) => { if (isTerminal(s)) void loadCodebase() })

// If the scan's codebase stops being visible (DAST access revoked while watching), the API answers 404:
// the live stream ends and the user is sent back to the project list.
watch(error, (e) => {
  if (e?.status === 404) {
    toast.error('Codebase not found.')
    void navigateTo('/')
  }
})

const cancelling = ref(false)
async function cancel() {
  cancelling.value = true
  try {
    await api.scans.cancel(id.value)
    toast.info('Cancellation requested.')
  } catch (e) {
    toast.error(friendlyError(e).message)
  } finally {
    cancelling.value = false
  }
}
</script>

<template>
  <div>
    <LoadingState v-if="!scan && !error" />
    <ErrorState v-else-if="!scan && error" :error="error" not-found-message="Scan not found." @retry="restart" />
    <template v-else-if="scan">
      <PageHeader :title="`Scan #${scan.id}`">
        <template #breadcrumb>
          <AppBreadcrumb
            :items="[
              { label: 'Projects', to: '/' },
              codebase ? { label: codebase.project.name, to: `/projects/${codebase.project.id}` } : { label: 'Project' },
              { label: codebase?.name ?? 'Codebase', to: `/codebases/${scan.codebase_id}` },
              { label: 'Scan run' },
            ]"
          />
        </template>
        <template #meta>
          <p class="mt-1 flex flex-wrap items-center gap-2">
            <ScanStatusBadge :status="scan.status" />
            <UBadge color="neutral" variant="outline" size="sm" class="uppercase">{{ scan.type }}</UBadge>
            <UBadge color="neutral" variant="outline" size="sm">{{ scan.coverage === 'partial' ? 'Partial' : 'Full' }}</UBadge>
            <UBadge v-if="authInfo?.authenticated" color="info" variant="subtle" size="sm" icon="i-lucide-lock-keyhole" data-testid="authenticated-scan">Authenticated scan</UBadge>
            <UBadge v-if="scan.active" color="warning" variant="subtle" size="sm" icon="i-lucide-shield-alert" data-testid="active-scan-badge">
              Active scan<template v-if="scan.active_timing"> + timing</template>
            </UBadge>
          </p>
        </template>
        <template #actions>
          <UButton v-if="isActive(scan.status)" color="neutral" variant="outline" icon="i-lucide-square" :loading="cancelling" data-testid="cancel-scan" @click="cancel">{{ cancelling ? 'Cancelling…' : 'Cancel scan' }}</UButton>
          <UButton v-if="scan.status === 'succeeded'" :to="`/codebases/${scan.codebase_id}`" data-testid="view-results">View results</UButton>
        </template>
      </PageHeader>

      <ErrorState v-if="error && error.status !== 404" :error="error" class="mb-3" @retry="restart" />

      <div class="grid gap-4 lg:grid-cols-3">
        <UCard>
          <h2 id="run-h" class="mb-2 text-base">Run</h2>
          <dl class="grid grid-cols-[7rem_1fr] gap-y-1">
            <dt class="text-muted">Queued</dt><dd><LocalTime :value="scan.queued_at" empty="–" /></dd>
            <dt class="text-muted">Started</dt><dd><LocalTime :value="scan.started_at" empty="–" /></dd>
            <dt class="text-muted">Finished</dt><dd><LocalTime :value="scan.finished_at" empty="–" /></dd>
            <template v-if="formatDuration(scan.started_at, scan.finished_at)"><dt class="text-muted">Duration</dt><dd>{{ formatDuration(scan.started_at, scan.finished_at) }}</dd></template>
            <template v-if="scan.ref"><dt class="text-muted">Ref</dt><dd class="font-mono text-xs">{{ scan.ref }}</dd></template>
            <template v-if="scan.engine"><dt class="text-muted">Engine</dt><dd class="text-xs">{{ scan.engine }} {{ scan.engine_version }}</dd></template>
            <template v-if="authInfo?.authenticated"><dt class="text-muted">Login</dt><dd data-testid="scan-auth-mode">{{ authInfo.mode ?? 'yes' }}</dd></template>
            <template v-if="authInfo?.pages !== null && authInfo?.pages !== undefined"><dt class="text-muted">Pages scanned</dt><dd data-testid="scan-pages">{{ authInfo.pages }}</dd></template>
            <template v-if="activeInfo?.requests !== null && activeInfo?.requests !== undefined"><dt class="text-muted">Active requests sent</dt><dd data-testid="scan-active-requests">{{ activeInfo.requests }}</dd></template>
          </dl>
          <p v-if="!isTerminal(scan.status)" class="mt-3 text-xs text-muted">Live updates: {{ transport === 'sse' ? 'streaming' : transport === 'polling' ? 'refreshing every 2 seconds' : 'connecting' }}.</p>
        </UCard>

        <UCard class="lg:col-span-2">
          <h2 id="out-h" class="mb-2 text-base">Result</h2>
          <p v-if="scan.status === 'queued'" class="text-muted">Waiting for a worker to pick this scan up.</p>
          <p v-else-if="scan.status === 'running'" class="text-muted">The scan is running. This page updates by itself.</p>
          <template v-else-if="scan.status === 'succeeded'">
            <SeverityCounts v-if="scan.summary" :summary="scan.summary" />
            <p v-else class="text-muted">The scan finished.</p>
            <p class="mt-2"><NuxtLink :to="`/codebases/${scan.codebase_id}`" class="text-primary hover:underline">Open the codebase findings</NuxtLink></p>
          </template>
          <UAlert v-else-if="scan.status === 'failed'" color="error" variant="subtle" role="alert" data-testid="scan-failed" title="The scan failed.">
            <template #description>
              <p>{{ scanErrorText(scan.error_code) || 'The scan could not be completed.' }}</p>
              <p class="mt-1 text-xs text-muted">The codebase's findings were not changed.</p>
            </template>
          </UAlert>
          <p v-else class="text-muted">The scan was cancelled. The codebase's findings were not changed.</p>
        </UCard>
      </div>

      <UCard class="mt-4">
        <h2 id="log-h" class="mb-2 text-base">Log</h2>
        <pre ref="logEl" class="max-h-80 overflow-auto rounded-md bg-inverted p-3 text-xs leading-5 text-inverted" tabindex="0" aria-label="Scan log" data-testid="scan-log">{{ lines.length ? lines.join('\n') : 'No log lines yet.' }}</pre>
      </UCard>
    </template>
  </div>
</template>
