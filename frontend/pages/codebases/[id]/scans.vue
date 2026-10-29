<script setup lang="ts">
import type { TableColumn } from '@nuxt/ui'
import { formatDuration } from '~/utils/format'
import type { CompareStatus, Scan } from '~/types/api'

// Scan history and comparison (new / unchanged / fixed). Selection and tab live in the URL.
const { codebase } = useCodebase()
const api = useApi()
const route = useRoute()
const router = useRouter()

const page = useRouteQuery('page', 1)
const cstatus = useRouteQuery<string>('status', 'new')
const cpage = useRouteQuery('cpage', 1)
const base = computed(() => Number(route.query.base) || undefined)
const head = computed(() => Number(route.query.head) || undefined)
const comparing = computed(() => route.query.compare === '1' || (!!base.value && !!head.value))

const { data, error, pending, reload } = useLoad(
  () => api.codebases.scans(codebase.value!.id, { page: page.value, page_size: 25 }),
  { watch: [page, () => codebase.value?.latest_scan?.id] },
)

const columns: TableColumn<Scan>[] = [
  { id: 'select', header: () => h('span', { class: 'sr-only' }, 'Select for comparison') },
  { id: 'scan', header: 'Scan' },
  { id: 'started', header: 'Started' },
  { id: 'type', header: 'Type' },
  { id: 'coverage', header: 'Coverage' },
  { id: 'trigger', header: 'Trigger' },
  { id: 'status', header: 'Status' },
  { id: 'ref', header: 'Ref' },
  { id: 'engine', header: 'Engine' },
  { id: 'findings', header: 'Findings' },
]

const selected = ref<number[]>([])
function toggle(id: number, on: boolean) {
  const set = selected.value.filter(x => x !== id)
  if (on) set.push(id)
  selected.value = set.slice(-2)
}

const TRIGGER: Record<string, string> = { manual: 'Manual', schedule: 'Scheduled', ci: 'CI' }

/** Older scan is the base, newer the head. */
function openCompare(ids?: number[]) {
  const query = { ...route.query }
  delete query.cpage
  delete query.status
  if (ids && ids.length === 2) {
    const scans = (data.value?.items ?? []).filter(s => ids.includes(s.id))
    const sorted = [...scans].sort((a, b) => (a.started_at ?? '').localeCompare(b.started_at ?? '') || a.id - b.id)
    const [older, newer] = sorted.length === 2 ? sorted : [{ id: Math.min(...ids) }, { id: Math.max(...ids) }]
    query.base = String(older!.id)
    query.head = String(newer!.id)
  } else {
    delete query.base
    delete query.head
  }
  query.compare = '1'
  void router.replace({ query })
}

function closeCompare() {
  const query = { ...route.query }
  for (const k of ['base', 'head', 'compare', 'status', 'cpage']) delete query[k]
  void router.replace({ query })
}

const cmp = useLoad(
  () => (comparing.value
    ? api.codebases.compare(codebase.value!.id, { base: base.value, head: head.value, status: cstatus.value as CompareStatus, page: cpage.value, page_size: 50 })
    : Promise.resolve(undefined)),
  { watch: [comparing, base, head, cstatus, cpage] },
)

const tabs = computed(() => (['new', 'unchanged', 'fixed'] as CompareStatus[]).map(k => ({
  label: `${k.charAt(0).toUpperCase()}${k.slice(1)} (${cmp.data.value?.counts[k] ?? 0})`,
  value: k,
})))
const compareFindings = computed(() => (cmp.data.value?.items ?? []).map(i => i.finding))
const scanLabel = (s: { id: number } | null | undefined) => (s ? `#${s.id}` : 'none')
</script>

<template>
  <div class="space-y-6">
    <section aria-labelledby="hist-h">
      <div class="mb-2 flex flex-wrap items-center justify-between gap-2">
        <h2 id="hist-h">Scan history</h2>
        <div class="flex flex-wrap gap-2">
          <UButton color="neutral" variant="outline" size="xs" icon="i-lucide-history" :disabled="selected.length !== 2" data-testid="compare-selected" @click="openCompare(selected)">Compare selected (2)</UButton>
          <UButton color="neutral" variant="outline" size="xs" data-testid="compare-latest" @click="openCompare()">Compare latest two</UButton>
        </div>
      </div>
      <LoadingState v-if="pending && !data" />
      <ErrorState v-else-if="error && !data" :error="error" not-found-message="Codebase not found." @retry="reload" />
      <UCard v-else-if="data" :ui="{ body: 'p-0 sm:p-0' }">
        <EmptyState v-if="data.items.length === 0" title="No scans yet" hint="Run a scan, or send results from CI." />
        <template v-else>
          <UTable :data="data.items" :columns="columns" caption="Scan history" data-testid="scans-table" :ui="{ root: 'overflow-x-auto', td: 'align-top', caption: 'sr-only' }">
            <template #select-cell="{ row }">
              <UCheckbox :model-value="selected.includes(row.original.id)" :disabled="row.original.status !== 'succeeded'" :aria-label="`Select scan ${row.original.id} for comparison`" @update:model-value="toggle(row.original.id, $event === true)" />
            </template>
            <template #scan-cell="{ row }"><NuxtLink :to="`/scans/${row.original.id}`" class="text-primary hover:underline">#{{ row.original.id }}</NuxtLink></template>
            <template #started-cell="{ row }">
              <span class="whitespace-nowrap"><LocalTime :value="row.original.started_at ?? row.original.queued_at" /><span v-if="formatDuration(row.original.started_at, row.original.finished_at)" class="text-muted"> · {{ formatDuration(row.original.started_at, row.original.finished_at) }}</span></span>
            </template>
            <template #type-cell="{ row }"><span class="uppercase">{{ row.original.type }}</span></template>
            <template #coverage-cell="{ row }">
              {{ row.original.coverage === 'partial' ? 'Partial' : 'Full' }}<span v-if="row.original.coverage === 'partial' && row.original.scanned_file_count" class="text-muted"> ({{ row.original.scanned_file_count }} files)</span>
              <UBadge v-if="row.original.active" color="warning" variant="subtle" size="sm" class="ml-1" icon="i-lucide-shield-alert" data-testid="active-scan-badge">
                Active<template v-if="row.original.active_timing"> + timing</template>
              </UBadge>
            </template>
            <template #trigger-cell="{ row }">{{ TRIGGER[row.original.trigger] ?? row.original.trigger }}</template>
            <template #status-cell="{ row }"><ScanStatusBadge :status="row.original.status" /></template>
            <template #ref-cell="{ row }"><span class="font-mono text-xs">{{ row.original.ref }}</span></template>
            <template #engine-cell="{ row }"><span class="text-xs">{{ row.original.engine }}<template v-if="row.original.engine_version"> {{ row.original.engine_version }}</template></span></template>
            <template #findings-cell="{ row }">
              <SeverityCounts v-if="row.original.summary" :summary="row.original.summary" compact />
              <span v-else class="text-muted">&ndash;</span>
            </template>
          </UTable>
          <PagerBar :page="data.page" :page-size="data.page_size" :total="data.total" @update:page="page = $event" />
        </template>
      </UCard>
    </section>

    <section v-if="comparing" aria-labelledby="cmp-h" data-testid="compare-section">
      <div class="mb-2 flex items-center justify-between gap-2">
        <h2 id="cmp-h">Compare</h2>
        <UButton color="neutral" variant="ghost" size="xs" icon="i-lucide-x" @click="closeCompare">Close comparison</UButton>
      </div>
      <LoadingState v-if="cmp.pending.value && !cmp.data.value" />
      <ErrorState v-else-if="cmp.error.value && !cmp.data.value" :error="cmp.error.value" @retry="cmp.reload" />
      <UCard v-else-if="cmp.data.value" :ui="{ body: 'p-0 sm:p-0' }">
        <div class="p-4 pb-0">
          <p class="text-muted">
            Base: <strong>{{ cmp.data.value.base ? scanLabel(cmp.data.value.base) : 'none (no earlier scan)' }}</strong>
            &rarr; Head: <strong>{{ scanLabel(cmp.data.value.head) }}</strong>
          </p>
          <UAlert v-if="cmp.data.value.scope.kind === 'partial'" class="mt-2" color="warning" variant="subtle" role="status" data-testid="partial-banner" :description="`Partial scan: compared only ${cmp.data.value.scope.file_count ?? 0} scanned files.`" />
          <UAlert v-if="cmp.data.value.warning" class="mt-2" color="warning" variant="subtle" role="status" data-testid="compare-warning" :description="cmp.data.value.warning.message" />
        </div>
        <UTabs :items="tabs" :model-value="cstatus" :content="false" class="mt-3 px-4" aria-label="Comparison result" @update:model-value="cstatus = String($event); cpage = 1" />
        <EmptyState v-if="compareFindings.length === 0" :title="`No ${cstatus} findings`" />
        <template v-else>
          <FindingTable :items="compareFindings" :caption="`${cstatus} findings`" />
          <PagerBar :page="cmp.data.value.page" :page-size="cmp.data.value.page_size" :total="cmp.data.value.total" @update:page="cpage = $event" />
        </template>
      </UCard>
    </section>
  </div>
</template>
