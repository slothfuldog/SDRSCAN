<script setup lang="ts">
import type { DastStatus } from '~/types/api'

// Target authorization status (text always visible). Only rendered for URL targets, which the server sends
// only to Admins and Members with DAST access.
defineProps<{ status: DastStatus | null | undefined }>()
</script>

<template>
  <UBadge v-if="status === 'confirmed'" color="success" variant="subtle" size="sm" icon="i-lucide-check" data-testid="dast-status">Confirmed</UBadge>
  <UBadge v-else-if="status === 'pending_confirmation'" color="warning" variant="subtle" size="sm" icon="i-lucide-clock" data-testid="dast-status">Pending confirmation</UBadge>
</template>
