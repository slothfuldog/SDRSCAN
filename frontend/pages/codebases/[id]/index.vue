<script setup lang="ts">
import { SEVERITIES, SEVERITY_LABEL, parseSeverityList } from '~/utils/severity'
import { isAdvisoryId } from '~/utils/vuln'
import { plural } from '~/utils/format'
import type { Severity } from '~/types/api'

// Findings of the Codebase's latest state, filterable by severity / rule / text / path. State lives in the URL.
const { codebase } = useCodebase()
const api = useApi()
const route = useRoute()
const router = useRouter()

const PAGE_SIZE = 50
const ALL = '__all__'
const page = useRouteQuery('page', 1)
const rule = useRouteQuery('rule', '', { resetPage: true })
const q = useRouteQuery('q', '', { resetPage: true })
const path = useRouteQuery('path', '', { resetPage: true })
const low = useRouteQuery('low', '', { resetPage: true })
const kindRaw = useRouteQuery('kind', '', { resetPage: true })
const kind = computed<'' | 'code' | 'vulnerability'>(() => (kindRaw.value === 'code' || kindRaw.value === 'vulnerability' ? kindRaw.value : ''))
const confRaw = useRouteQuery('confidence', '', { resetPage: true })
const scopeRaw = useRouteQuery('scope', '', { resetPage: true })
const vconf = computed<'' | 'high' | 'low'>(() => (confRaw.value === 'high' || confRaw.value === 'low' ? confRaw.value : ''))
const vscope = computed<'' | 'runtime' | 'dev'>(() => (scopeRaw.value === 'runtime' || scopeRaw.value === 'dev' ? scopeRaw.value : ''))
// CVE box: a complete advisory id filters exactly (`cve=`), anything else is a text search (`q=`) when the Search box is empty.
const cve = useRouteQuery('cve', '', { resetPage: true })
const cveExact = computed(() => (isAdvisoryId(cve.value) ? cve.value.trim() : ''))
const cvePartial = computed(() => (cve.value && !cveExact.value ? cve.value.trim() : ''))
const effectiveQ = computed(() => q.value || cvePartial.value)
const severities = computed(() => parseSeverityList(route.query.severity))

const search = ref(q.value)
let timer: ReturnType<typeof setTimeout> | undefined
watch(search, (v) => {
  clearTimeout(timer)
  timer = setTimeout(() => { q.value = v.trim() }, 300)
})
watch(q, (v) => { if (v !== search.value.trim()) search.value = v })
const cveSearch = ref(cve.value)
let cveTimer: ReturnType<typeof setTimeout> | undefined
watch(cveSearch, (v) => {
  clearTimeout(cveTimer)
  cveTimer = setTimeout(() => { cve.value = v.trim() }, 300)
})
watch(cve, (v) => { if (v !== cveSearch.value.trim()) cveSearch.value = v })
onBeforeUnmount(() => { clearTimeout(timer); clearTimeout(cveTimer) })

function toggleSeverity(s: Severity, on: boolean) {
  const set = new Set(severities.value)
  if (on) set.add(s)
  else set.delete(s)
  const list = SEVERITIES.filter(x => set.has(x))
  const query = { ...route.query }
  if (list.length) query.severity = list.join(',')
  else delete query.severity
  delete query.page
  void router.replace({ query })
}

function clearFilters() {
  void router.replace({ query: {} })
  search.value = ''
  cveSearch.value = ''
}

const filtersActive = computed(() => severities.value.length > 0 || !!rule.value || !!q.value || !!path.value || !!low.value || !!kind.value || !!cve.value || !!vconf.value || !!vscope.value)

const { data, error, pending, reload } = useLoad(
  () => api.codebases.findings(codebase.value!.id, {
    page: page.value,
    page_size: PAGE_SIZE,
    severity: severities.value,
    rule: rule.value,
    q: effectiveQ.value,
    kind: kind.value || undefined,
    cve: cveExact.value || undefined,
    confidence: vconf.value || undefined,
    scope: vscope.value || undefined,
    path: path.value,
    include_low_confidence: low.value === '1' ? true : undefined,
    sort: 'severity',
  }),
  { watch: [page, rule, q, path, low, kind, cve, vconf, vscope, () => route.query.severity, () => codebase.value?.latest_scan?.id] },
)

// facets.rule comes from the server (counted with every active filter except the rule itself).
const ruleItems = computed(() => [{ label: 'All rules', value: ALL }, ...(data.value?.facets.rule ?? []).map(r => ({ label: `${r.id} (${r.count})`, value: r.id }))])
const kindItems = computed(() => {
  const k = data.value?.facets.kind
  return [
    { label: 'All types', value: ALL },
    { label: `Code${k ? ` (${k.code})` : ''}`, value: 'code' },
    { label: `Vulnerability${k ? ` (${k.vulnerability})` : ''}`, value: 'vulnerability' },
  ]
})
const confItems = computed(() => {
  const c = data.value?.facets.confidence
  return [
    { label: 'All', value: ALL },
    { label: `High${c ? ` (${c.high})` : ''}`, value: 'high' },
    { label: `Low${c ? ` (${c.low})` : ''}`, value: 'low' },
  ]
})
const scopeItems = computed(() => {
  const c = data.value?.facets.scope
  return [
    { label: 'All', value: ALL },
    { label: `Runtime${c ? ` (${c.runtime})` : ''}`, value: 'runtime' },
    { label: `Dev${c ? ` (${c.dev})` : ''}`, value: 'dev' },
  ]
})
// The two vulnerability filters only make sense once the codebase has CVE findings (or while one is applied).
const showVulnFilters = computed(() => (data.value?.facets.kind?.vulnerability ?? 0) > 0 || !!vconf.value || !!vscope.value)
const vulnerablePackages = computed(() => data.value?.facets.vulnerable_packages ?? 0)
const sevFacet = (s: Severity) => data.value?.facets.severity[s]
</script>

<template>
  <div>
    <UCard class="mb-4" aria-label="Filters">
      <div class="flex flex-wrap items-end gap-x-6 gap-y-3">
        <fieldset>
          <legend class="mb-1 text-sm font-medium text-highlighted">Severity</legend>
          <div class="flex flex-wrap gap-x-4 gap-y-1">
            <UCheckbox
              v-for="s in SEVERITIES" :key="s" :model-value="severities.includes(s)"
              :label="`${SEVERITY_LABEL[s]}${sevFacet(s) !== undefined ? ` (${sevFacet(s)})` : ''}`" @update:model-value="toggleSeverity(s, $event === true)"
            />
          </div>
        </fieldset>
        <UFormField label="Rule" name="rule" class="min-w-[12rem]">
          <USelect id="f-rule" :model-value="rule || ALL" :items="ruleItems" class="w-full" @update:model-value="rule = $event === ALL ? '' : String($event)" />
        </UFormField>
        <UFormField label="Type" name="kind" class="min-w-[11rem]">
          <USelect id="f-kind" :model-value="kind || ALL" :items="kindItems" class="w-full" @update:model-value="kindRaw = $event === ALL ? '' : String($event)" />
        </UFormField>
        <UFormField v-if="showVulnFilters" label="Confidence" name="confidence" class="min-w-[9rem]">
          <USelect id="f-confidence" :model-value="vconf || ALL" :items="confItems" class="w-full" @update:model-value="confRaw = $event === ALL ? '' : String($event)" />
        </UFormField>
        <UFormField v-if="showVulnFilters" label="Scope" name="scope" class="min-w-[9rem]">
          <USelect id="f-scope" :model-value="vscope || ALL" :items="scopeItems" class="w-full" @update:model-value="scopeRaw = $event === ALL ? '' : String($event)" />
        </UFormField>
        <UFormField label="CVE" name="cve" class="min-w-[12rem]" :hint="cvePartial && q ? 'Search text takes precedence' : undefined">
          <UInput id="f-cve" v-model="cveSearch" type="search" class="w-full" placeholder="CVE-2024-12345 or part of an ID" autocomplete="off" icon="i-lucide-shield-alert" maxlength="64" />
        </UFormField>
        <UFormField label="Search" name="q" class="min-w-[12rem] flex-1">
          <UInput id="f-q" v-model="search" type="search" class="w-full" placeholder="Path, URL, message or package" autocomplete="off" icon="i-lucide-search" />
        </UFormField>
        <UCheckbox class="pb-1.5" :model-value="low === '1'" label="Show low-confidence findings" @update:model-value="low = $event === true ? '1' : ''" />
      </div>
      <p v-if="path" class="mt-3 flex items-center gap-2 text-xs" data-testid="path-filter">
        <UBadge color="neutral" variant="outline">Path: <code class="ml-1">{{ path }}</code></UBadge>
        <UButton color="neutral" variant="ghost" size="xs" icon="i-lucide-x" @click="path = '';">Clear path filter</UButton>
      </p>
      <p v-if="filtersActive" class="mt-2"><UButton color="neutral" variant="outline" size="xs" @click="clearFilters">Clear all filters</UButton></p>
    </UCard>

    <p v-if="vulnerablePackages > 0" class="mb-3 flex flex-wrap items-center gap-2" data-testid="vulnerable-packages">
      <UBadge color="primary" variant="subtle" icon="i-lucide-shield-alert">{{ plural(vulnerablePackages, 'vulnerable dependency', 'vulnerable dependencies') }}</UBadge>
      <UButton v-if="kind !== 'vulnerability'" color="neutral" variant="ghost" size="xs" @click="kindRaw = 'vulnerability';">Show vulnerabilities only</UButton>
    </p>

    <LoadingState v-if="pending && !data" />
    <ErrorState v-else-if="error && !data" :error="error" not-found-message="Codebase not found." @retry="reload" />
    <UCard v-else-if="data" :ui="{ body: 'p-0 sm:p-0' }" :aria-busy="pending">
      <ErrorState v-if="error" :error="error" class="m-3" @retry="reload" />
      <EmptyState
        v-if="data.items.length === 0"
        :title="filtersActive ? 'No findings match these filters' : (codebase?.summary ? 'No findings in the latest state' : 'No findings yet')"
        :hint="filtersActive ? 'Try removing a filter.' : (codebase?.summary ? undefined : 'Run a scan to see findings.')"
      />
      <template v-else>
        <FindingTable :items="data.items" caption="Findings" />
        <PagerBar :page="data.page" :page-size="data.page_size" :total="data.total" @update:page="page = $event" />
      </template>
    </UCard>
  </div>
</template>
