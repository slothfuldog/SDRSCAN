<script setup lang="ts">
import { formatDateTime, utcTitle } from '~/utils/format'

// Shows the browser-local time; the title attribute holds the exact UTC value.
defineProps<{ value: string | null | undefined, empty?: string }>()
</script>

<template>
  <time v-if="value" :datetime="value" :title="utcTitle(value)">{{ formatDateTime(value) }}</time>
  <span v-else class="text-muted">{{ empty ?? '' }}</span>
</template>
