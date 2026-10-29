<script setup lang="ts">
import { formatRetry, isApiError } from '~/utils/errors'
import { safeNextPath } from '~/utils/format'

definePageMeta({ layout: 'auth' })
useHead({ title: 'Sign in · SDRScan' })

const auth = useAuth()
const route = useRoute()
const state = reactive({ username: '', password: '' })
const busy = ref(false)

const fe = useFormErrors({
  validate: () => {
    const errors: Record<string, string> = {}
    if (!state.username.trim()) errors.username = 'Username is required.'
    if (!state.password) errors.password = 'Password is required.'
    return errors
  },
})
fe.autoClear(() => ({ ...state }))

async function submit() {
  if (busy.value || !fe.check()) return
  busy.value = true
  try {
    await auth.login(state.username.trim(), state.password)
    state.password = ''
    await navigateTo(auth.mustChangePassword ? '/account' : safeNextPath(route.query.next), { replace: true })
  } catch (e) {
    if (isApiError(e) && e.status === 401) fe.formError.value = 'Invalid username or password.'
    else if (isApiError(e) && e.status === 429) fe.formError.value = e.retryAfter ? `Too many attempts. Try again in ${formatRetry(e.retryAfter)}.` : 'Too many attempts. Please wait and try again.'
    else fe.fromServer(e)
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <UCard>
    <h1 class="mb-4 text-xl">Sign in</h1>
    <UAlert v-if="auth.bootError" class="mb-4" color="error" variant="subtle" role="alert" description="Cannot reach the server. Check your connection and try again." />
    <UForm :loading-auto="false" :state="state" novalidate class="space-y-4" @submit="submit">
      <FormErrorSummary error-testid="login-error" />
      <AppField name="username" label="Username" required>
        <UInput id="username" v-model="state.username" class="w-full" autocomplete="username" autocapitalize="none" spellcheck="false" autofocus :disabled="busy" />
      </AppField>
      <AppField name="password" label="Password" required>
        <UInput id="password" v-model="state.password" type="password" class="w-full" autocomplete="current-password" :disabled="busy" />
      </AppField>
      <UButton type="submit" block :loading="busy">{{ busy ? 'Signing in…' : 'Sign in' }}</UButton>
    </UForm>
  </UCard>
</template>
