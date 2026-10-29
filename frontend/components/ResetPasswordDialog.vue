<script setup lang="ts">
import { validateNewPassword } from '~/utils/validators'
import type { UserRow } from '~/types/api'

// Admin sets a temporary password. All sessions of that user are revoked and a change is required at next sign-in.
const props = defineProps<{ open: boolean, user: UserRow | null }>()
const emit = defineEmits<{ close: [], done: [] }>()

const api = useApi()
const state = reactive({ new_password: '' })
const busy = ref(false)

const fe = useFormErrors({
  validate: () => {
    const m = validateNewPassword(state.new_password, props.user?.username, 'New password')
    return m ? { new_password: m } : {}
  },
})
fe.autoClear(() => ({ ...state }))

watch(() => props.open, (o) => { if (o) { state.new_password = ''; fe.reset() } })

async function submit() {
  if (!props.user || busy.value || !fe.check()) return
  busy.value = true
  try {
    await api.users.resetPassword(props.user.id, state.new_password)
    state.new_password = ''
    emit('done')
  } catch (e) {
    fe.fromServer(e)
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <ModalDialog :open="open" :title="`Reset password for ${user?.username ?? ''}`" :busy="busy" @close="emit('close')">
    <UForm id="reset-pw-form" :loading-auto="false" :state="state" novalidate class="space-y-4" @submit="submit">
      <p class="text-muted">The user is signed out everywhere and must choose a new password at the next sign-in.</p>
      <FormErrorSummary />
      <AppField name="new_password" label="Temporary password" required help="12 to 128 characters.">
        <UInput id="rp-pw" v-model="state.new_password" data-autofocus type="password" class="w-full" autocomplete="new-password" :disabled="busy" />
      </AppField>
    </UForm>
    <template #footer>
      <UButton color="neutral" variant="outline" :disabled="busy" @click="emit('close')">Cancel</UButton>
      <UButton type="submit" form="reset-pw-form" :loading="busy">{{ busy ? 'Resetting…' : 'Reset password' }}</UButton>
    </template>
  </ModalDialog>
</template>
