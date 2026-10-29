<script setup lang="ts">
const props = defineProps<{ page: number, pageSize: number, total: number }>()
const emit = defineEmits<{ 'update:page': [number] }>()
const from = computed(() => (props.total === 0 ? 0 : (props.page - 1) * props.pageSize + 1))
const to = computed(() => Math.min(props.total, props.page * props.pageSize))
</script>

<template>
  <nav v-if="total > 0" class="flex flex-wrap items-center justify-between gap-2 px-3 py-2 text-xs" aria-label="Pagination">
    <p class="text-muted" aria-live="polite">Showing {{ from }}–{{ to }} of {{ total }}</p>
    <UPagination v-if="total > pageSize" :page="page" :items-per-page="pageSize" :total="total" size="xs" @update:page="emit('update:page', $event)" />
  </nav>
</template>
