<script setup lang="ts">
defineProps<{ title: string, subtitle?: string }>()
</script>

<template>
  <div class="mb-4 flex flex-wrap items-start justify-between gap-3">
    <div class="min-w-0">
      <slot name="breadcrumb" />
      <h1 class="break-words">{{ title }}</h1>
      <p v-if="subtitle" class="mt-0.5 text-muted">{{ subtitle }}</p>
      <slot name="meta" />
    </div>
    <div class="flex flex-wrap items-center gap-2"><slot name="actions" /></div>
  </div>
</template>
