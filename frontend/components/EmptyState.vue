<script setup lang="ts">
defineProps<{ title: string, hint?: string }>()
</script>

<template>
  <div class="px-4 py-10 text-center">
    <p class="font-medium text-highlighted">{{ title }}</p>
    <p v-if="hint" class="mt-1 text-muted">{{ hint }}</p>
    <div class="mt-3 flex justify-center"><slot /></div>
  </div>
</template>
