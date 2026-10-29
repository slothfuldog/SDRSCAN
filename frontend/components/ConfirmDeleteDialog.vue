<script setup lang="ts">

// Permanent delete: the user must type the exact name before the button is enabled (the server re-checks ?confirm=<name>).
const props = defineProps<{
  open: boolean
  kind: 'Project' | 'Codebase'
  name: string
  /** Performs the DELETE; may throw. */
  action: () => Promise<unknown>
}>()
const emit = defineEmits<{ close: [], deleted: [] }>()

const state = reactive({ typed: '' })
const busy = ref(false)

// The server checks ?confirm=<name>: its error on "confirm" belongs to the field "typed".
const fe = useFormErrors({
  aliases: { confirm: 'typed' },
  validate: () => {
    if (!state.typed) return { typed: `Type the exact name “${props.name}” to confirm.` }
    return state.typed === props.name ? {} : { typed: `“${state.typed}” does not match. Type “${props.name}” exactly.` }
  },
})
fe.autoClear(() => ({ ...state }))

watch(() => props.open, (o) => { if (o) { state.typed = ''; fe.reset() } })

async function confirm() {
  if (busy.value || !fe.check()) return
  busy.value = true
  try {
    await props.action()
    emit('deleted')
  } catch (e) {
    fe.fromServer(e)
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <ModalDialog :open="open" :title="`Delete ${kind.toLowerCase()}`" :busy="busy" @close="emit('close')">
    <UForm id="confirm-delete-form" :loading-auto="false" :state="state" novalidate class="space-y-4" @submit="confirm">
      <UAlert
        color="warning" variant="subtle" icon="i-lucide-triangle-alert" title="This is permanent."
        :description="`${kind === 'Project' ? 'Deleting this project also deletes all of its codebases, scans and findings.' : 'Deleting this codebase also deletes all of its scans and findings.'} There is no undo.`"
      />
      <FormErrorSummary />
      <AppField name="typed" required>
        <template #label>Type <code class="rounded bg-elevated px-1">{{ name }}</code> to confirm</template>
        <UInput id="confirm-name" v-model="state.typed" data-autofocus class="w-full" autocomplete="off" spellcheck="false" :disabled="busy" />
      </AppField>
    </UForm>
    <template #footer>
      <UButton color="neutral" variant="outline" :disabled="busy" @click="emit('close')">Cancel</UButton>
      <UButton type="submit" form="confirm-delete-form" color="error" icon="i-lucide-trash-2" :disabled="busy" :loading="busy">{{ busy ? 'Deleting…' : `Delete ${kind.toLowerCase()}` }}</UButton>
    </template>
  </ModalDialog>
</template>
