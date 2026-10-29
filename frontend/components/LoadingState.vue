<script setup lang="ts">
withDefaults(defineProps<{ label?: string }>(), { label: 'Loading…' })
</script>

<template>
  <div class="flex items-center gap-2 py-8 text-muted" role="status" aria-live="polite">
    <UIcon name="i-lucide-loader-circle" class="size-[18px] motion-safe:animate-spin" aria-hidden="true" /> <span>{{ label }}</span>
  </div>
</template>
