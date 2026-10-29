<script setup lang="ts">
import { SEVERITY_COLOR, SEVERITY_LABEL, isSeverity } from '~/utils/severity'

// Always shows the severity as text, never as colour alone. Critical is a solid badge, the rest are subtle.
const props = defineProps<{ severity: string | null | undefined, count?: number }>()
const known = computed(() => (isSeverity(props.severity) ? props.severity : null))
const label = computed(() => (known.value ? SEVERITY_LABEL[known.value] : String(props.severity ?? '')))
</script>

<template>
  <UBadge :color="known ? SEVERITY_COLOR[known] : 'neutral'" :variant="known === 'critical' ? 'solid' : 'subtle'" size="sm" class="font-semibold" data-testid="severity-badge">
    {{ label }}<template v-if="count !== undefined"> <span class="tabular-nums">{{ count }}</span></template>
  </UBadge>
</template>
