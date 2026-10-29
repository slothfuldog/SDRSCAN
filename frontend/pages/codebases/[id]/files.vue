<script setup lang="ts">
import type { TableColumn } from '@nuxt/ui'
import { SEVERITIES, highestSeverity } from '~/utils/severity'
import type { FileRow, Severity } from '~/types/api'

// Per-file (or per-URL for DAST) summary of the latest state. Clicking a row opens the findings filtered to it.
const { codebase } = useCodebase()
const api = useApi()
const page = useRouteQuery('page', 1)
const isUrl = computed(() => codebase.value?.target_type === 'url')

const { data, error, pending, reload } = useLoad(
  () => api.codebases.files(codebase.value!.id, { page: page.value, page_size: 50 }),
  { watch: [page, () => codebase.value?.latest_scan?.id] },
)

const columns = computed<TableColumn<FileRow>[]>(() => [
  { id: 'location', header: isUrl.value ? 'URL' : 'File' },
  { id: 'highest', header: 'Highest' },
  ...SEVERITIES.map(s => ({ id: s, header: s.charAt(0).toUpperCase() + s.slice(1), meta: { class: { th: 'text-right', td: 'text-right' } } })),
  { id: 'total', header: 'Total', meta: { class: { th: 'text-right', td: 'text-right' } } },
])

function findingsLink(row: FileRow) {
  const key = (row.kind ?? (isUrl.value ? 'url' : 'file')) === 'url' ? 'q' : 'path'
  return { path: `/codebases/${codebase.value!.id}`, query: { [key]: row.location } }
}
const top = (r: FileRow) => highestSeverity(r as Partial<Record<Severity, number>>)
const count = (r: FileRow, s: Severity) => r[s] ?? 0
</script>

<template>
  <LoadingState v-if="pending && !data" />
  <ErrorState v-else-if="error && !data" :error="error" not-found-message="Codebase not found." @retry="reload" />
  <UCard v-else-if="data" :ui="{ body: 'p-0 sm:p-0' }">
    <EmptyState v-if="data.items.length === 0" :title="isUrl ? 'No affected URLs' : 'No affected files'" hint="Files appear here when a scan reports findings in them." />
    <template v-else>
      <UTable :data="data.items" :columns="columns" :caption="isUrl ? 'Affected URLs' : 'Affected files'" data-testid="files-table" :ui="{ root: 'overflow-x-auto', caption: 'sr-only' }">
        <template #location-cell="{ row }"><NuxtLink :to="findingsLink(row.original)" class="block max-w-[28rem] break-all font-mono text-xs text-primary hover:underline">{{ row.original.location }}</NuxtLink></template>
        <template #highest-cell="{ row }"><SeverityBadge v-if="top(row.original)" :severity="top(row.original)" /></template>
        <template v-for="s in SEVERITIES" :key="s" #[`${s}-cell`]="{ row }">
          <span class="tabular-nums" :class="count(row.original, s) === 0 ? 'text-dimmed' : ''">{{ count(row.original, s) }}</span>
        </template>
        <template #total-cell="{ row }"><span class="font-medium tabular-nums">{{ row.original.total }}</span></template>
      </UTable>
      <PagerBar :page="data.page" :page-size="data.page_size" :total="data.total" @update:page="page = $event" />
    </template>
  </UCard>
</template>
