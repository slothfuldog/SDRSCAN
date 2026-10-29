<script setup lang="ts">
import { validateNewPassword } from '~/utils/validators'

useHead({ title: 'Account · SDRScan' })

const auth = useAuth()
const api = useApi()
const toast = useNotify()

const state = reactive({ current_password: '', new_password: '', confirm_password: '' })
const busy = ref(false)

const fe = useFormErrors({
  validate: () => {
    const errors: Record<string, string> = {}
    if (!state.current_password) errors.current_password = 'Current password is required.'
    if (!state.new_password) errors.new_password = 'New password is required.'
    else {
      const n = validateNewPassword(state.new_password, auth.user?.username, 'New password')
      if (n) errors.new_password = n
      else if (state.new_password === state.current_password) errors.new_password = 'The new password must differ from the current one.'
    }
    if (!state.confirm_password) errors.confirm_password = 'Confirm the new password.'
    else if (state.confirm_password !== state.new_password) errors.confirm_password = 'The passwords do not match.'
    return errors
  },
})
fe.autoClear(() => ({ ...state }))

async function submit() {
  if (busy.value || !fe.check()) return
  busy.value = true
  try {
    await api.auth.changePassword(state.current_password, state.new_password)
    const forced = auth.mustChangePassword
    auth.passwordChanged()
    Object.assign(state, { current_password: '', new_password: '', confirm_password: '' })
    fe.reset()
    toast.success('Password changed. Other sessions were signed out.')
    if (forced) await navigateTo('/')
  } catch (e) {
    fe.fromServer(e)
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <div class="max-w-xl">
    <PageHeader title="Account" />

    <UAlert v-if="auth.mustChangePassword" class="mb-4" color="warning" variant="subtle" icon="i-lucide-triangle-alert" role="alert" data-testid="must-change" title="You must change your password before you can continue." description="It was set by an Admin." />

    <UCard class="mb-4">
      <h2 id="profile-h" class="mb-2">Profile</h2>
      <dl class="grid grid-cols-[8rem_1fr] gap-y-1">
        <dt class="text-muted">Username</dt><dd>{{ auth.user?.username }}</dd>
        <dt class="text-muted">Role</dt><dd>{{ auth.user?.role === 'admin' ? 'Admin' : 'Member' }}</dd>
        <dt class="text-muted">DAST access</dt><dd>{{ auth.hasDastAccess ? 'Yes' : 'No' }}<span v-if="auth.user?.role === 'admin'" class="text-muted"> (Admins always have it)</span></dd>
      </dl>
    </UCard>

    <UCard>
      <h2 id="pw-h" class="mb-3">Change password</h2>
      <UForm :loading-auto="false" :state="state" novalidate class="space-y-4" @submit="submit">
        <FormErrorSummary />
        <AppField name="current_password" label="Current password" required>
          <UInput id="cur-pw" v-model="state.current_password" type="password" class="w-full" autocomplete="current-password" :disabled="busy" />
        </AppField>
        <AppField name="new_password" label="New password" required help="12 to 128 characters. No composition rules.">
          <UInput id="new-pw" v-model="state.new_password" type="password" class="w-full" autocomplete="new-password" :disabled="busy" />
        </AppField>
        <AppField name="confirm_password" label="Confirm new password" required>
          <UInput id="conf-pw" v-model="state.confirm_password" type="password" class="w-full" autocomplete="new-password" :disabled="busy" />
        </AppField>
        <UButton type="submit" :loading="busy">{{ busy ? 'Saving…' : 'Change password' }}</UButton>
      </UForm>
    </UCard>
  </div>
</template>
