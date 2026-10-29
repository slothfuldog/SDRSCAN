<script setup lang="ts">
import { SEVERITIES, SEVERITY_COLOR, SEVERITY_LABEL } from '~/utils/severity'
import type { Severity } from '~/types/api'

// Five counters. Zero counts are muted (neutral outline); each one carries its text label for assistive technology.
defineProps<{ summary: Partial<Record<Severity, number>>, compact?: boolean }>()
</script>

<template>
  <ul class="flex flex-wrap gap-1.5" aria-label="Findings by severity">
    <li v-for="s in SEVERITIES" :key="s">
      <UBadge
        :color="(summary[s] ?? 0) > 0 ? SEVERITY_COLOR[s] : 'neutral'" :variant="(summary[s] ?? 0) > 0 ? (s === 'critical' ? 'solid' : 'subtle') : 'outline'"
        size="sm" class="tabular-nums" :title="`${SEVERITY_LABEL[s]}: ${summary[s] ?? 0}`"
      >
        <span v-if="!compact">{{ SEVERITY_LABEL[s] }}</span>
        <template v-else><span aria-hidden="true">{{ SEVERITY_LABEL[s].charAt(0) }}</span><span class="sr-only">{{ SEVERITY_LABEL[s] }}</span></template>
        <span class="font-bold">{{ summary[s] ?? 0 }}</span>
      </UBadge>
    </li>
  </ul>
</template>
