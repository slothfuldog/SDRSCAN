<script setup lang="ts">
import { cweUrl } from '~/utils/format'

const api = useApi()
const route = useRoute()
const id = computed(() => Number(route.params.id))

const { data: f, error, pending, reload } = useLoad(() => api.findings.get(id.value), { watch: [id] })
const { data: codebase } = useLoad(async () => (f.value ? api.codebases.get(f.value.codebase_id) : undefined), { watch: [() => f.value?.codebase_id], immediate: false })
useHead(() => ({ title: `${f.value?.rule_id ?? 'Finding'} · SDRScan` }))

const loc = computed(() => f.value?.location)
const fileLoc = computed(() => (loc.value?.kind === 'file' ? loc.value : null))
const hasRegion = computed(() => !!fileLoc.value?.start_line)
const lineRange = computed(() => {
  const l = fileLoc.value
  if (!l?.start_line) return ''
  const end = l.end_line ?? l.start_line
  const lines = end === l.start_line ? `Line ${l.start_line}` : `Lines ${l.start_line} to ${end}`
  if (l.start_column) {
    const ec = l.end_column ? ` to ${l.end_column}` : ''
    return `${lines}, column ${l.start_column}${ec}`
  }
  return lines
})
</script>

<template>
  <div>
    <LoadingState v-if="pending && f?.id !== id" />
    <ErrorState v-else-if="error && !f" :error="error" not-found-message="Finding not found." @retry="reload" />
    <template v-else-if="f">
      <PageHeader :title="f.rule_id">
        <template #breadcrumb>
          <AppBreadcrumb
            :items="[
              { label: 'Projects', to: '/' },
              codebase ? { label: codebase.project.name, to: `/projects/${codebase.project.id}` } : { label: 'Project' },
              { label: codebase?.name ?? 'Codebase', to: `/codebases/${f.codebase_id}` },
              { label: `Finding #${f.id}` },
            ]"
          />
        </template>
        <template #meta>
          <p class="mt-1 flex flex-wrap items-center gap-2">
            <SeverityBadge :severity="f.severity" />
            <FindingTypeChip :kind="f.vulnerability ? 'vulnerability' : 'code'" />
            <UBadge v-if="f.confidence === 'low'" color="neutral" variant="outline" size="sm">Low confidence</UBadge>
            <UBadge v-if="f.vulnerability?.confidence === 'low'" color="warning" variant="outline" size="sm" title="Version-based detection, may be patched by the vendor." data-testid="vuln-low-confidence">Confidence: low</UBadge>
            <UBadge v-if="f.vulnerability?.scope" color="neutral" variant="subtle" size="sm" data-testid="vuln-scope-badge">{{ f.vulnerability.scope === 'dev' ? 'Dev' : 'Runtime' }}</UBadge>
            <UBadge v-if="f.is_current === false" color="warning" variant="subtle" size="sm" title="This finding is from an older scan and is not part of the codebase's latest state">Not in latest state</UBadge>
          </p>
        </template>
        <template #actions>
          <UButton :to="`/codebases/${f.codebase_id}`" color="neutral" variant="outline">Back to findings</UButton>
        </template>
      </PageHeader>

      <div class="grid gap-4 lg:grid-cols-3">
        <div class="space-y-4 lg:col-span-2">
        <VulnerabilityPanel v-if="f.vulnerability" :vulnerability="f.vulnerability" :location="f.location" />
        <UCard>
          <h2 id="problem-h" class="mb-1 text-base">Problem</h2>
          <p class="mb-4 whitespace-pre-wrap break-words" data-testid="finding-message">{{ f.message }}</p>

          <h2 class="mb-2 text-base">{{ loc?.kind === 'url' ? 'Evidence' : 'Problem area' }}</h2>
          <template v-if="loc?.kind === 'url'">
            <p class="mb-2 text-xs text-muted">Request and response evidence. Sensitive values are hidden.</p>
            <SnippetView :snippet="f.snippet" kind="url" :redacted="f.redacted" />
          </template>
          <template v-else-if="hasRegion">
            <SnippetView
              :snippet="f.snippet" kind="file" :start-line="fileLoc?.start_line" :end-line="fileLoc?.end_line"
              :start-column="fileLoc?.start_column" :redacted="f.redacted"
            />
            <p class="mt-2 text-xs text-muted">Only the flagged region is shown. The full source file is not stored, so there are no surrounding lines.</p>
          </template>
          <template v-else>
            <p class="text-muted">No line information is available for this finding. Only the file path is known.</p>
            <SnippetView v-if="f.snippet" class="mt-2" :snippet="f.snippet" kind="url" :redacted="f.redacted" />
          </template>
        </UCard>
        </div>

        <UCard>
          <h2 id="details-h" class="mb-2 text-base">Details</h2>
          <dl class="space-y-3">
            <div>
              <dt class="text-xs uppercase tracking-wide text-muted">{{ loc?.kind === 'url' ? 'URL' : 'File' }}</dt>
              <dd class="break-all font-mono text-xs" data-testid="finding-location">{{ loc?.kind === 'url' ? loc.url : fileLoc?.path }}</dd>
            </div>
            <div v-if="lineRange">
              <dt class="text-xs uppercase tracking-wide text-muted">Position</dt>
              <dd>{{ lineRange }}</dd>
            </div>
            <div>
              <dt class="text-xs uppercase tracking-wide text-muted">Rule</dt>
              <dd class="font-mono text-xs">{{ f.rule_id }}</dd>
            </div>
            <div>
              <dt class="text-xs uppercase tracking-wide text-muted">CWE</dt>
              <dd v-if="f.cwe?.length" class="flex flex-wrap gap-2">
                <template v-for="c in f.cwe" :key="c">
                  <a v-if="cweUrl(c)" :href="cweUrl(c)!" target="_blank" rel="noopener noreferrer" class="inline-flex items-center gap-1 text-primary hover:underline">{{ c }} <AppIcon name="external" :size="12" /></a>
                  <span v-else>{{ c }}</span>
                </template>
              </dd>
              <dd v-else class="text-muted">None</dd>
            </div>
            <div>
              <dt class="text-xs uppercase tracking-wide text-muted">Reported by</dt>
              <dd><NuxtLink :to="`/scans/${f.scan_id}`" class="text-primary hover:underline">Scan #{{ f.scan_id }}</NuxtLink></dd>
            </div>
            <div v-if="f.fingerprint">
              <dt class="text-xs uppercase tracking-wide text-muted">Fingerprint</dt>
              <dd class="break-all font-mono text-xs">{{ f.fingerprint }}</dd>
            </div>
          </dl>
        </UCard>
      </div>
    </template>
  </div>
</template>
