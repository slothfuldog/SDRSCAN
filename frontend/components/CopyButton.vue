<script setup lang="ts">
const props = defineProps<{ value: string, label?: string }>()
const copied = ref(false)
async function copy() {
  try {
    await navigator.clipboard.writeText(props.value)
    copied.value = true
    setTimeout(() => { copied.value = false }, 2000)
  } catch {
    copied.value = false
  }
}
</script>

<template>
  <UButton color="neutral" variant="outline" size="xs" :icon="copied ? 'i-lucide-check' : 'i-lucide-copy'" @click="copy">{{ copied ? 'Copied' : (label ?? 'Copy') }}</UButton>
</template>
