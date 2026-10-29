<script setup lang="ts">
// Nuxt UI modal (Reka UI dialog: role=dialog, aria-modal, focus trap, Escape, focus restore).
// `[data-autofocus]` inside the body receives focus on open instead of the close button.
const props = withDefaults(defineProps<{ open: boolean, title: string, size?: 'sm' | 'md' | 'lg', busy?: boolean, description?: string }>(), { size: 'md', busy: false, description: undefined })
const emit = defineEmits<{ close: [] }>()

const widths = { sm: 'sm:max-w-sm', md: 'sm:max-w-lg', lg: 'sm:max-w-2xl' }

function onOpenAutoFocus(e: Event) {
  const target = document.querySelector<HTMLElement>('[role="dialog"] [data-autofocus]')
  if (target) {
    e.preventDefault()
    target.focus()
  }
}

function update(v: boolean) {
  if (!v && !props.busy) emit('close')
}
</script>

<template>
  <UModal
    :open="open" :title="title" :description="description" :dismissible="!busy" :close="!busy" :ui="{ content: widths[size], title: 'break-words' }"
    :content="{ onOpenAutoFocus }" @update:open="update"
  >
    <template #body><slot /></template>
    <template v-if="$slots.footer" #footer><div class="flex w-full flex-wrap justify-end gap-2"><slot name="footer" /></div></template>
  </UModal>
</template>
