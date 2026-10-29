<script setup lang="ts">
import { advisoryUrl } from '~/utils/vuln'

// An advisory id (CVE, GHSA or OSV id) as a badge. With `link`, CVE ids link to NVD and GHSA ids to GitHub,
// but only when the id matches the strict pattern; every other value (including hostile text) stays plain text.
const props = withDefaults(defineProps<{ id: string, link?: boolean }>(), { link: false })
const url = computed(() => (props.link ? advisoryUrl(props.id) : null))
const base = 'inline-flex items-center gap-1 rounded-md bg-elevated px-1.5 py-0.5 font-mono text-xs ring ring-inset ring-default'
</script>

<template>
  <a
    v-if="url" :href="url" target="_blank" rel="noopener noreferrer" :class="[base, 'text-primary hover:underline']"
    data-testid="cve-badge" :aria-label="`${id} (opens in a new tab)`"
  >{{ id }}<AppIcon name="external" :size="11" /></a>
  <span v-else :class="[base, 'text-highlighted']" data-testid="cve-badge">{{ id }}</span>
</template>
