<script setup lang="ts">
import { ACTIVE_SCANNING_RISK_NOTE, ACTIVE_SCANNING_STATEMENT } from '~/utils/dastAuth'
import type { Codebase } from '~/types/api'

// Authorizing ACTIVE (payload-sending) scanning: a separate, stricter layer on top of the basic DAST
// target confirmation. Modelled on ConfirmDeleteDialog: an explicit checkbox AND the codebase name
// typed back exactly, as deliberate friction for a riskier action.
const props = defineProps<{ open: boolean, codebase: Codebase }>()
const emit = defineEmits<{ close: [], authorized: [] }>()

const api = useApi()
const state = reactive({ accepted: false, typed: '' })
const busy = ref(false)

const fe = useFormErrors({
  aliases: { statement_accepted: 'accepted', codebase_name: 'typed' },
  validate: () => {
    const errs: Record<string, string> = {}
    if (!state.accepted) errs.accepted = 'Check the box to confirm you understand the risks of active scanning.'
    if (!state.typed) errs.typed = `Type the exact name “${props.codebase.name}” to confirm.`
    else if (state.typed !== props.codebase.name) errs.typed = `“${state.typed}” does not match. Type “${props.codebase.name}” exactly.`
    return errs
  },
})
fe.autoClear(() => ({ ...state }))

watch(() => props.open, (o) => { if (o) { state.accepted = false; state.typed = ''; fe.reset() } })

async function submit() {
  if (busy.value || !fe.check()) return
  busy.value = true
  try {
    await api.codebases.authorizeActiveScanning(props.codebase.id, { statement_accepted: state.accepted, codebase_name: state.typed })
    emit('authorized')
  } catch (e) {
    fe.fromServer(e)
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <ModalDialog :open="open" title="Authorize active scanning" :busy="busy" @close="emit('close')">
    <UForm id="authorize-active-form" :loading-auto="false" :state="state" novalidate class="space-y-4" @submit="submit">
      <p class="text-muted">Target: <code class="break-all">{{ codebase.base_url }}</code></p>
      <UAlert color="warning" variant="subtle" icon="i-lucide-triangle-alert" title="This is a risky action." :description="ACTIVE_SCANNING_RISK_NOTE" />
      <FormErrorSummary />
      <AppField name="accepted" required>
        <UCheckbox v-model="state.accepted" :label="ACTIVE_SCANNING_STATEMENT" data-autofocus data-testid="active-statement" :disabled="busy" />
      </AppField>
      <AppField name="typed" required>
        <template #label>Type <code class="rounded bg-elevated px-1">{{ codebase.name }}</code> to confirm</template>
        <UInput id="active-confirm-name" v-model="state.typed" class="w-full" autocomplete="off" spellcheck="false" :disabled="busy" data-testid="active-confirm-name" />
      </AppField>
    </UForm>
    <template #footer>
      <UButton color="neutral" variant="outline" :disabled="busy" @click="emit('close')">Cancel</UButton>
      <UButton type="submit" form="authorize-active-form" color="warning" icon="i-lucide-shield-alert" :loading="busy" data-testid="authorize-active-submit">
        {{ busy ? 'Authorizing…' : 'Authorize active scanning' }}
      </UButton>
    </template>
  </ModalDialog>
</template>
