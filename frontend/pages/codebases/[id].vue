<script setup lang="ts">
import { highestSeverity } from '~/utils/severity'
import { isActive } from '~/utils/scanStream'
import { CODEBASE_KEY } from '~/composables/useCodebase'
import { codebaseTarget } from '~/utils/format'

const api = useApi()
const route = useRoute()
const id = computed(() => Number(route.params.id))

const { data: codebase, error, pending, reload } = useLoad(() => api.codebases.get(id.value), { watch: [id] })
provide(CODEBASE_KEY, { codebase, reload })
useHead(() => ({ title: `${codebase.value?.name ?? 'Codebase'} · SDRScan` }))

const tabs = computed(() => [
  { label: 'Findings', value: `/codebases/${id.value}`, icon: 'i-lucide-shield-alert' },
  { label: 'Files', value: `/codebases/${id.value}/files`, icon: 'i-lucide-file' },
  { label: 'Scan history', value: `/codebases/${id.value}/scans`, icon: 'i-lucide-history' },
  { label: 'Settings', value: `/codebases/${id.value}/settings`, icon: 'i-lucide-settings' },
])
const activeTab = computed(() => {
  const exact = tabs.value.find(t => t.value === route.path)
  if (exact) return exact.value
  return tabs.value.slice(1).find(t => route.path.startsWith(t.value))?.value ?? tabs.value[0]!.value
})

const activeScan = computed(() => (codebase.value?.active_scan && isActive(codebase.value.active_scan.status) ? codebase.value.active_scan : null))
const highest = computed(() => codebase.value?.summary?.highest_severity ?? highestSeverity(codebase.value?.summary))
// URL targets exist only for Admins and DAST holders; if access is revoked while the page is open the next request is a 404.
const targetLike = computed(() => codebase.value && {
  id: codebase.value.id, name: codebase.value.name, target_type: codebase.value.target_type, dast: codebase.value.dast, dast_active: codebase.value.dast_active,
})
</script>

<template>
  <div>
    <LoadingState v-if="pending && codebase?.id !== id && !error" />
    <ErrorState v-else-if="error && (!codebase || error.status === 404)" :error="error" not-found-message="Codebase not found." @retry="reload" />
    <template v-else-if="codebase">
      <PageHeader :title="codebase.name">
        <template #breadcrumb>
          <AppBreadcrumb :items="[{ label: 'Projects', to: '/' }, { label: codebase.project.name, to: `/projects/${codebase.project.id}` }, { label: codebase.name }]" />
        </template>
        <template #meta>
          <p class="mt-1 flex flex-wrap items-center gap-2">
            <UBadge color="neutral" variant="outline" size="sm">{{ codebase.target_type === 'url' ? 'URL (DAST)' : 'Repository (SAST)' }}</UBadge>
            <DastStatusBadge v-if="codebase.dast" :status="codebase.dast.status" />
            <span class="break-all font-mono text-xs text-muted">{{ codebaseTarget(codebase) }}<template v-if="codebase.subdirectory"> / {{ codebase.subdirectory }}</template></span>
          </p>
        </template>
        <template #actions>
          <RunScanButton v-if="targetLike" :codebase="targetLike" :disabled-extra="!!activeScan" />
        </template>
      </PageHeader>

      <UCard class="mb-4" data-testid="codebase-summary">
        <template v-if="codebase.summary">
          <div class="flex flex-wrap items-center gap-3">
            <SeverityCounts :summary="codebase.summary" />
            <span v-if="highest" class="text-muted">Highest: <SeverityBadge :severity="highest" /></span>
            <span v-else class="text-muted">No findings in the latest state.</span>
          </div>
          <p v-if="codebase.state && codebase.state.partial_scans_since_base > 0" class="mt-1 text-xs text-muted" data-testid="partial-note">
            Based on full scan #{{ codebase.state.base_scan_id }} plus {{ codebase.state.partial_scans_since_base }} partial scan{{ codebase.state.partial_scans_since_base === 1 ? '' : 's' }}.
          </p>
          <p v-else-if="codebase.state" class="mt-1 text-xs text-muted">Based on full scan #{{ codebase.state.base_scan_id }}.</p>
        </template>
        <p v-else class="text-muted" data-testid="not-scanned">Not scanned yet. Run a scan to see findings.</p>
      </UCard>

      <ActiveScanPanel v-if="activeScan" :key="activeScan.id" :scan="activeScan" class="mb-4" @finished="reload" />

      <UTabs :items="tabs" :model-value="activeTab" :content="false" aria-label="Codebase sections" class="mb-4" @update:model-value="navigateTo(String($event))" />

      <NuxtPage />
    </template>
  </div>
</template>
