<script setup lang="ts">
import type { TableColumn } from '@nuxt/ui'
import { friendlyError } from '~/utils/errors'
import { formatDuration } from '~/utils/format'
import { ageLabel, sourceLabel } from '~/utils/vuln'
import type { VulnDbErrorCode, VulnDbSource, VulnDbUpdate, VulnDbUpdateState } from '~/types/api'

useHead({ title: 'Vulnerability database · SDRScan' })

// Admin page: status of the advisory database (OSV / NVD data used for CVE checks) and the "Update now" job.
// While an update runs the page reloads GET /system/vulndb every 2 seconds.
const POLL_MS = 2000

const auth = useAuth()
const api = useApi()
const toast = useNotify()

const { data, error, pending, reload } = useLoad(() => (auth.isAdmin ? api.system.vulndb() : Promise.resolve(undefined)))

const now = computed(() => { void data.value; return Date.now() })
const running = computed(() => data.value?.update?.state === 'running')

let timer: ReturnType<typeof setInterval> | undefined
function stopPolling() {
  if (timer !== undefined) clearInterval(timer)
  timer = undefined
}
watch(running, (r) => {
  stopPolling()
  if (r) timer = setInterval(() => { void reload() }, POLL_MS)
}, { immediate: true })
onBeforeUnmount(stopPolling)

watch(() => data.value?.update, (cur, prev) => {
  if (!prev || !cur || prev.id !== cur.id || prev.state !== 'running' || cur.state === 'running') return
  if (cur.state === 'succeeded') toast.success('Vulnerability database updated.')
  else if (cur.state === 'cancelled') toast.info('Vulnerability database update cancelled.')
  else toast.error(`Vulnerability database update failed. ${ERROR_TEXT[cur.error_code ?? 'update_failed']}`)
})

const ERROR_TEXT: Record<VulnDbErrorCode, string> = {
  timeout: 'The update timed out.',
  update_failed: 'The update tool reported an error.',
  tool_not_found: 'The sdrscan-vuln tool was not found.',
  cancelled: 'The update was cancelled.',
}
const STATE_LABEL: Record<VulnDbUpdateState, string> = { running: 'Running', succeeded: 'Succeeded', failed: 'Failed', cancelled: 'Cancelled' }
const STATE_COLOR: Record<VulnDbUpdateState, 'info' | 'success' | 'error' | 'neutral'> = { running: 'info', succeeded: 'success', failed: 'error', cancelled: 'neutral' }

const installed = computed(() => !!data.value?.configured && !!data.value.status?.installed)
const canUpdate = computed(() => !!data.value?.configured && !!data.value.tool.available && !running.value)
const updateHint = computed(() => {
  const d = data.value
  if (!d) return ''
  if (running.value) return 'An update is already running.'
  if (!d.configured) return 'Set SDRSCAN_VULN_DB on the server first.'
  if (!d.tool.available) return 'The sdrscan-vuln tool is not available on the server.'
  return ''
})

const columns: TableColumn<VulnDbSource>[] = [
  { id: 'source', header: 'Source' },
  { id: 'ecosystem', header: 'Ecosystem' },
  { id: 'advisories', header: 'Advisories', meta: { class: { th: 'text-right', td: 'text-right' } } },
  { id: 'updated', header: 'Last updated' },
]

// ---- update dialog -------------------------------------------------------------------------------------
const dialogOpen = ref(false)
const selected = ref<string[]>([])
const nvd = ref(false)
const busy = ref(false)

const fe = useFormErrors({
  validate: () => (selected.value.length === 0 ? { ecosystems: 'Select at least one ecosystem.' } : {}),
})
fe.autoClear(() => ({ ecosystems: selected.value.join(','), nvd: nvd.value }))

function openDialog() {
  selected.value = [...(data.value?.ecosystems ?? [])]
  nvd.value = false
  fe.reset()
  dialogOpen.value = true
}
async function startUpdate() {
  if (busy.value || !fe.check()) return
  busy.value = true
  try {
    await api.system.vulndbUpdate({ ecosystems: (data.value?.ecosystems ?? []).filter(e => selected.value.includes(e)), nvd: nvd.value })
    dialogOpen.value = false
    toast.info('Vulnerability database update started.')
    await reload()
  } catch (e) {
    fe.fromServer(e)
    if (isConflict(e)) await reload()
  } finally {
    busy.value = false
  }
}
const isConflict = (e: unknown) => friendlyError(e).kind === 'conflict'

const cancelling = ref(false)
async function cancelUpdate() {
  cancelling.value = true
  try {
    await api.system.vulndbCancel()
    await reload()
  } catch (e) {
    toast.error(friendlyError(e).message)
    await reload()
  } finally {
    cancelling.value = false
  }
}

const duration = (u: VulnDbUpdate) => formatDuration(u.started_at, u.finished_at)
</script>

<template>
  <div>
    <PageHeader title="Vulnerability database" subtitle="Advisory data (OSV and NVD) used to report vulnerable dependencies and known product CVEs.">
      <template v-if="auth.isAdmin" #actions>
        <UButton color="neutral" variant="outline" icon="i-lucide-refresh-cw" :loading="pending && !!data" data-testid="refresh-vulndb" @click="reload">Refresh</UButton>
        <UButton icon="i-lucide-download" :disabled="!canUpdate" :title="updateHint || undefined" data-testid="update-now" @click="openDialog">Update now</UButton>
      </template>
    </PageHeader>

    <AdminOnly>
      <LoadingState v-if="pending && !data" />
      <ErrorState v-else-if="error && !data" :error="error" @retry="reload" />
      <div v-else-if="data" class="space-y-4">
        <UAlert
          v-if="!installed" color="warning" variant="subtle" icon="i-lucide-triangle-alert" data-testid="warn-off"
          title="CVE checks are off until the database is installed."
          :description="!data.configured
            ? 'No database directory is configured on the server (SDRSCAN_VULN_DB is empty). Set it to a directory, restart the backend, then run an update.'
            : (data.db_present ? 'The database directory has no advisory data yet. Run an update to install it.' : 'The database directory does not exist yet. Run an update to create and fill it.')"
        />
        <UAlert
          v-if="data.configured && !data.sca_enabled" color="info" variant="subtle" icon="i-lucide-info" data-testid="warn-sca-off"
          title="Dependency scanning (SCA) is turned off." description="SDRSCAN_SCA_ENABLED is false on the server, so scans do not use the database even when it is installed."
        />
        <UAlert
          v-if="data.configured && !data.tool.available" color="warning" variant="subtle" icon="i-lucide-triangle-alert" data-testid="warn-tool"
          title="The update tool is not available." :description="`sdrscan-vuln was not found (${data.tool.path}). The database cannot be updated from here.`"
        />
        <UAlert
          v-if="installed && data.stale" color="warning" variant="subtle" icon="i-lucide-clock" data-testid="warn-stale"
          :title="`The vulnerability data is older than ${data.status?.max_age_days ?? data.stale_after_days} days.`" :description="`Last updated ${ageLabel(data.status?.age_days, data.status?.updated_at, now) || 'a long time ago'}. New CVEs published since then are not reported. Run an update.`"
        />
        <UAlert
          v-if="data.status_error && data.tool.available" color="warning" variant="subtle" icon="i-lucide-triangle-alert" data-testid="warn-status-error"
          title="The database status could not be read." :description="data.status_error"
        />

        <div class="grid gap-4 sm:grid-cols-3" data-testid="vulndb-status">
          <UCard>
            <p class="text-xs uppercase tracking-wide text-muted">Database</p>
            <p class="mt-1">
              <UBadge v-if="installed" color="success" variant="subtle">Installed</UBadge>
              <UBadge v-else color="neutral" variant="subtle">Not installed</UBadge>
            </p>
            <p v-if="data.db_path" class="mt-2 break-all font-mono text-xs text-muted" data-testid="vulndb-path">{{ data.db_path }}</p>
          </UCard>
          <UCard>
            <p class="text-xs uppercase tracking-wide text-muted">Advisories</p>
            <p class="mt-1 text-2xl font-semibold tabular-nums" data-testid="advisory-count">{{ data.status?.advisory_count ?? 0 }}</p>
          </UCard>
          <UCard>
            <p class="text-xs uppercase tracking-wide text-muted">Oldest data</p>
            <p class="mt-1 text-2xl font-semibold" data-testid="data-age">{{ ageLabel(data.status?.age_days, data.status?.updated_at, now) || 'No data' }}</p>
            <p v-if="data.status?.updated_at" class="text-xs text-muted"><LocalTime :value="data.status.updated_at" /></p>
          </UCard>
        </div>

        <UCard :ui="{ body: 'p-0 sm:p-0' }">
          <template #header><h2 class="text-base">Sources</h2></template>
          <EmptyState v-if="!data.status || data.status.sources.length === 0" title="No source data yet" hint="Run an update to download advisories." />
          <UTable v-else :data="data.status.sources" :columns="columns" caption="Advisory sources" data-testid="sources-table" :ui="{ root: 'overflow-x-auto', caption: 'sr-only' }">
            <template #source-cell="{ row }">{{ sourceLabel(row.original.name) }}</template>
            <template #ecosystem-cell="{ row }">
              <span>{{ row.original.ecosystem ?? 'Products (DAST)' }}</span>
              <ul v-if="row.original.products?.length" class="mt-1 space-y-0.5 text-xs text-muted" data-testid="nvd-products" aria-label="Products covered by NVD">
                <li v-for="p in row.original.products" :key="p" class="break-all font-mono">{{ p }}</li>
              </ul>
            </template>
            <template #advisories-cell="{ row }"><span class="tabular-nums">{{ row.original.advisories }}</span></template>
            <template #updated-cell="{ row }">
              <span v-if="row.original.updated_at"><LocalTime :value="row.original.updated_at" /> <span class="text-xs text-muted" data-testid="source-age">({{ ageLabel(row.original.age_days, row.original.updated_at, now) }})</span></span>
              <span v-else class="text-muted">Never</span>
            </template>
          </UTable>
        </UCard>

        <UCard data-testid="update-card">
          <template #header>
            <div class="flex flex-wrap items-center justify-between gap-2">
              <h2 class="text-base">Update</h2>
              <UButton v-if="running" color="error" variant="outline" size="sm" icon="i-lucide-square" :loading="cancelling" data-testid="cancel-update" @click="cancelUpdate">Cancel update</UButton>
            </div>
          </template>
          <p v-if="!data.update" class="text-muted" data-testid="no-update">No update has run since the server started.</p>
          <div v-else data-testid="update-job">
            <p class="flex flex-wrap items-center gap-2">
              <UBadge :color="STATE_COLOR[data.update.state]" variant="subtle" :icon="data.update.state === 'running' ? 'i-lucide-loader-circle' : undefined" :ui="{ leadingIcon: 'motion-safe:animate-spin' }" data-testid="update-state">{{ STATE_LABEL[data.update.state] }}</UBadge>
              <span class="text-sm text-muted">
                Started <LocalTime :value="data.update.started_at" /> · {{ data.update.trigger === 'schedule' ? 'scheduled' : `by ${data.update.requested_by ?? 'unknown'}` }}
                <template v-if="duration(data.update)"> · took {{ duration(data.update) }}</template>
              </span>
            </p>
            <p class="mt-2 text-sm">
              Ecosystems: <span class="font-medium">{{ data.update.ecosystems.length ? data.update.ecosystems.join(', ') : 'default' }}</span><template v-if="data.update.nvd">, plus NVD</template>
            </p>
            <p v-if="data.update.state === 'failed' || data.update.state === 'cancelled'" class="mt-2 text-sm font-medium" :class="data.update.state === 'failed' ? 'text-error' : 'text-muted'" data-testid="update-error">
              {{ ERROR_TEXT[data.update.error_code ?? 'update_failed'] }}<template v-if="data.update.exit_code !== null"> (exit code {{ data.update.exit_code }})</template>
            </p>
            <h3 class="mb-1 mt-3 text-sm">Log</h3>
            <pre v-if="data.update.log_tail" class="max-h-72 overflow-auto rounded-md bg-inverted p-3 text-xs leading-5 text-inverted" tabindex="0" data-testid="update-log">{{ data.update.log_tail }}</pre>
            <p v-else class="text-sm text-muted">No output yet.</p>
          </div>
          <p class="mt-3 text-xs text-muted">
            Only one update runs at a time; it is stopped after {{ Math.round(data.update_timeout_seconds / 60) }} minutes.
            <template v-if="data.update_cron"> Scheduled updates: <code>{{ data.update_cron }}</code> (UTC).</template>
            <template v-else> Scheduled updates are not configured.</template>
          </p>
        </UCard>
      </div>
    </AdminOnly>

    <ModalDialog :open="dialogOpen" title="Update vulnerability database" :busy="busy" @close="dialogOpen = false">
      <form id="vulndb-form" novalidate class="space-y-4" @submit.prevent="startUpdate">
        <FormErrorSummary error-testid="update-form-error" />
        <AppField name="ecosystems" label="Ecosystems" required>
          <UCheckboxGroup v-model="selected" :items="data?.ecosystems ?? []" legend="Ecosystems" orientation="horizontal" :disabled="busy" :ui="{ legend: 'sr-only', fieldset: 'flex-wrap gap-x-5 gap-y-1' }" />
        </AppField>
        <UCheckbox v-model="nvd" label="Also update NVD data" description="Only needed for CVEs of products found by DAST (web servers, frameworks). OSV, selected above, covers dependency scanning (SCA). Larger download." :disabled="busy" />
        <p class="text-xs text-muted">The download can take a while. It runs in the background and you can leave this page.</p>
      </form>
      <template #footer>
        <UButton color="neutral" variant="outline" :disabled="busy" @click="dialogOpen = false;">Cancel</UButton>
        <UButton type="submit" form="vulndb-form" :loading="busy" data-testid="start-update">{{ busy ? 'Starting…' : 'Start update' }}</UButton>
      </template>
    </ModalDialog>
  </div>
</template>
