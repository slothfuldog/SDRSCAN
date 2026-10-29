<script setup lang="ts">
// Breadcrumb trail (Nuxt UI). The last item has no link and is the current page.
defineProps<{ items: Array<{ label: string, to?: string }> }>()
</script>

<template>
  <UBreadcrumb :items="items" class="mb-1 text-xs" />
</template>
