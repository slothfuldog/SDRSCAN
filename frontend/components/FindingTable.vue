<script setup lang="ts">
import type { TableColumn } from '@nuxt/ui'
import { locationLabel } from '~/utils/format'
import { isVulnerability, packageLabel } from '~/utils/vuln'
import type { FindingSummary } from '~/types/api'

// Findings as a Nuxt UI table. All values (path, URL, message, rule, package names, ids) are rendered as text.
defineProps<{ items: FindingSummary[], caption?: string }>()

const columns: TableColumn<FindingSummary>[] = [
  { id: 'severity', header: 'Severity' },
  { id: 'type', header: 'Type' },
  { id: 'rule', header: 'Rule / CVE' },
  { id: 'location', header: 'Location' },
  { id: 'message', header: 'Message' },
]

const MAX_IDS = 3
const shownIds = (f: FindingSummary) => (f.vulnerability?.ids ?? []).slice(0, MAX_IDS)
const moreIds = (f: FindingSummary) => Math.max(0, (f.vulnerability?.ids.length ?? 0) - MAX_IDS)
/** Findings of an active (payload-sending) DAST check: rule ids the engine prefixes with "dast-active-". */
const isActiveFinding = (f: FindingSummary) => f.rule_id.startsWith('dast-active-')
</script>

<template>
  <UTable :data="items" :columns="columns" :caption="caption" data-testid="finding-table" :ui="{ root: 'overflow-x-auto', td: 'align-top', caption: 'sr-only' }">
    <template #severity-cell="{ row }">
      <div class="flex flex-wrap items-center gap-1">
        <SeverityBadge :severity="row.original.severity" />
        <UBadge v-if="row.original.confidence === 'low'" color="neutral" variant="outline" size="sm" title="Low confidence finding">Low confidence</UBadge>
        <UBadge v-if="row.original.vulnerability?.confidence === 'low'" color="warning" variant="outline" size="sm" title="Version-based detection, may be patched by the vendor." data-testid="vuln-low-confidence">Confidence: low</UBadge>
      </div>
    </template>
    <template #type-cell="{ row }"><FindingTypeChip :kind="isVulnerability(row.original) ? 'vulnerability' : 'code'" /></template>
    <template #rule-cell="{ row }">
      <div v-if="row.original.vulnerability" class="flex min-w-[10rem] flex-col items-start gap-1" data-testid="vuln-cell">
        <div class="flex flex-wrap gap-1">
          <CveBadge v-for="id in shownIds(row.original)" :id="id" :key="id" />
          <span v-if="moreIds(row.original)" class="text-xs text-muted">+{{ moreIds(row.original) }} more</span>
          <UBadge v-if="row.original.vulnerability.scope === 'dev'" color="neutral" variant="subtle" size="sm" title="Development dependency" data-testid="vuln-dev-badge">Dev</UBadge>
        </div>
        <span v-if="packageLabel(row.original.vulnerability.package)" class="break-all font-mono text-xs text-muted" data-testid="vuln-package" :title="row.original.vulnerability.package?.product ?? undefined">{{ packageLabel(row.original.vulnerability.package) }}</span>
      </div>
      <span v-else class="flex flex-wrap items-center gap-1">
        <span class="whitespace-nowrap font-mono text-xs">{{ row.original.rule_id }}</span>
        <UBadge v-if="isActiveFinding(row.original)" color="warning" variant="subtle" size="sm" icon="i-lucide-shield-alert" title="Found by active (payload-sending) scanning" data-testid="active-finding-badge">Active</UBadge>
      </span>
    </template>
    <template #location-cell="{ row }">
      <NuxtLink :to="`/findings/${row.original.id}`" class="block max-w-[22rem] break-all font-mono text-xs text-primary hover:underline">{{ locationLabel(row.original.location) }}</NuxtLink>
    </template>
    <template #message-cell="{ row }"><span class="line-clamp-2 min-w-[14rem] max-w-prose whitespace-normal break-words">{{ row.original.message }}</span></template>
  </UTable>
</template>
