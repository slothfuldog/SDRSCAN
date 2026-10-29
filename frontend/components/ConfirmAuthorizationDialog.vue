<script setup lang="ts">
import type { Codebase } from '~/types/api'

// Admin-only. Shows the authorization statement exactly as the server sent it and requires an explicit checkbox.
const props = defineProps<{ open: boolean, codebase: Codebase }>()
const emit = defineEmits<{ close: [], confirmed: [] }>()

const api = useApi()
const state = reactive({ accepted: false })
const busy = ref(false)

const fe = useFormErrors({
  aliases: { statement_accepted: 'accepted' },
  validate: () => (state.accepted ? {} : { accepted: 'Accept the statement to confirm authorization.' }),
})
fe.autoClear(() => ({ ...state }))

watch(() => props.open, (o) => { if (o) { state.accepted = false; fe.reset() } })

async function submit() {
  if (busy.value || !props.codebase.confirmation_statement || !fe.check()) return
  busy.value = true
  try {
    await api.codebases.confirmAuthorization(props.codebase.id)
    emit('confirmed')
  } catch (e) {
    fe.fromServer(e)
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <ModalDialog :open="open" title="Confirm authorization" :busy="busy" @close="emit('close')">
    <UForm id="confirm-auth-form" :loading-auto="false" :state="state" novalidate @submit="submit">
      <p class="mb-2 text-muted">Target: <code class="break-all">{{ codebase.base_url }}</code></p>
      <blockquote v-if="codebase.confirmation_statement" class="rounded-md border-l-4 border-primary bg-elevated px-3 py-2" data-testid="statement">{{ codebase.confirmation_statement }}</blockquote>
      <UAlert v-else color="warning" variant="subtle" title="No statement to approve" description="The server did not send an authorization statement for this target. Reload the page." />
      <UAlert class="mt-3" color="warning" variant="subtle" icon="i-lucide-triangle-alert" description="If the base URL is changed later, the target returns to “Pending confirmation” and must be confirmed again." />
      <FormErrorSummary class="mt-3" />
      <AppField name="accepted" class="mt-4" required>
        <UCheckbox v-model="state.accepted" label="I accept this statement." data-autofocus data-testid="accept-statement" :disabled="busy || !codebase.confirmation_statement" />
      </AppField>
    </UForm>
    <template #footer>
      <UButton color="neutral" variant="outline" :disabled="busy" @click="emit('close')">Cancel</UButton>
      <UButton type="submit" form="confirm-auth-form" :disabled="!codebase.confirmation_statement" :loading="busy">{{ busy ? 'Confirming…' : 'Confirm authorization' }}</UButton>
    </template>
  </ModalDialog>
</template>
