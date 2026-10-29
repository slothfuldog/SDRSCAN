<script setup lang="ts">
import type { FindingKind } from '~/types/api'

// "Code" (SAST/DAST rule) or "Vulnerability" (known CVE in a dependency or product). Always text, never colour alone.
defineProps<{ kind: FindingKind }>()
</script>

<template>
  <UBadge
    v-if="kind === 'vulnerability'" color="primary" variant="subtle" size="sm" icon="i-lucide-shield-alert" data-testid="finding-kind"
    title="Known vulnerability (CVE) in a dependency or product"
  >Vulnerability</UBadge>
  <UBadge v-else color="neutral" variant="outline" size="sm" icon="i-lucide-code" data-testid="finding-kind" title="Code or configuration issue found by a rule">Code</UBadge>
</template>
