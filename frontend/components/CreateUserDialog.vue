<script setup lang="ts">
import { validateNewPassword, validateUsername } from '~/utils/validators'
import type { Role, UserRow } from '~/types/api'

// Admin: create an account. The password is temporary: the user must change it at first sign-in.
const props = defineProps<{ open: boolean }>()
const emit = defineEmits<{ close: [], created: [UserRow] }>()

const api = useApi()
const state = reactive<{ username: string, password: string, role: Role, canRunDast: boolean }>({ username: '', password: '', role: 'member', canRunDast: false })
const busy = ref(false)
const roles = [{ label: 'Member', value: 'member' }, { label: 'Admin', value: 'admin' }]

const fe = useFormErrors({
  validate: () => {
    const errors: Record<string, string> = {}
    const u = validateUsername(state.username.trim())
    if (u) errors.username = u
    const p = validateNewPassword(state.password, state.username.trim(), 'Password')
    if (p) errors.password = p
    if (state.role !== 'admin' && state.role !== 'member') errors.role = 'role must be \'admin\' or \'member\'.'
    return errors
  },
})
fe.autoClear(() => ({ ...state }))

watch(() => props.open, (o) => {
  if (!o) return
  Object.assign(state, { username: '', password: '', role: 'member', canRunDast: false })
  fe.reset()
})

async function submit() {
  if (busy.value || !fe.check()) return
  busy.value = true
  try {
    const user = await api.users.create({ username: state.username.trim(), password: state.password, role: state.role, can_run_dast: state.role === 'admin' ? undefined : state.canRunDast })
    state.password = ''
    emit('created', user)
  } catch (e) {
    fe.fromServer(e, { byCode: { username_taken: 'username' } })
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <ModalDialog :open="open" title="Create user" :busy="busy" @close="emit('close')">
    <UForm id="create-user-form" :loading-auto="false" :state="state" novalidate class="space-y-4" @submit="submit">
      <FormErrorSummary />
      <AppField name="username" label="Username" required help="3 to 64 characters: letters, digits, “.”, “_” or “-”.">
        <UInput id="nu-name" v-model="state.username" data-autofocus class="w-full" autocomplete="off" autocapitalize="none" spellcheck="false" :disabled="busy" />
      </AppField>
      <AppField name="password" label="Temporary password" required help="12 to 128 characters. The user must change it at first sign-in.">
        <UInput id="nu-pw" v-model="state.password" type="password" class="w-full" autocomplete="new-password" :disabled="busy" />
      </AppField>
      <AppField name="role" label="Role" required>
        <USelect id="nu-role" v-model="state.role" :items="roles" class="w-full" :disabled="busy" />
      </AppField>
      <UCheckbox v-if="state.role === 'member'" v-model="state.canRunDast" label="DAST access" description="Allows seeing and registering URL targets and running DAST scans." :disabled="busy" />
    </UForm>
    <template #footer>
      <UButton color="neutral" variant="outline" :disabled="busy" @click="emit('close')">Cancel</UButton>
      <UButton type="submit" form="create-user-form" :loading="busy">{{ busy ? 'Creating…' : 'Create user' }}</UButton>
    </template>
  </ModalDialog>
</template>
