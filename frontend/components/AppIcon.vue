<script setup lang="ts">
// Maps this app's short icon names to the locally bundled Lucide collection (no CDN). Rendered by Nuxt UI's UIcon.
const props = withDefaults(defineProps<{ name: string, size?: number }>(), { size: 16 })

const MAP: Record<string, string> = {
  shield: 'i-lucide-shield-check', folder: 'i-lucide-folder', code: 'i-lucide-code', globe: 'i-lucide-globe', user: 'i-lucide-user', users: 'i-lucide-users',
  key: 'i-lucide-key-round', activity: 'i-lucide-activity', logout: 'i-lucide-log-out', plus: 'i-lucide-plus', trash: 'i-lucide-trash-2', play: 'i-lucide-play',
  stop: 'i-lucide-square', refresh: 'i-lucide-refresh-cw', check: 'i-lucide-check', x: 'i-lucide-x', warning: 'i-lucide-triangle-alert', info: 'i-lucide-info',
  copy: 'i-lucide-copy', chevron: 'i-lucide-chevron-right', external: 'i-lucide-external-link', file: 'i-lucide-file', clock: 'i-lucide-clock', lock: 'i-lucide-lock',
  edit: 'i-lucide-pencil', move: 'i-lucide-move', history: 'i-lucide-history', calendar: 'i-lucide-calendar-clock', menu: 'i-lucide-menu',
}
const icon = computed(() => MAP[props.name] ?? 'i-lucide-circle')
</script>

<template>
  <UIcon :name="icon" :size="size" aria-hidden="true" class="shrink-0" />
</template>
