<script setup lang="ts">
import { friendlyError } from '~/utils/errors'
import { displayUser } from '~/utils/format'
import { hasDastAccess, TARGET_NOT_CONFIRMED_HINT } from '~/utils/permissions'
import {
  AUTH_LIMITS_NOTE, AUTH_TYPE_ITEMS, AUTH_TYPE_LABEL, MAX_COOKIES, MAX_EXTRA_FIELDS, MAX_HEADERS, TOKEN_EXAMPLE, TOKEN_FROM_ITEMS, TOKEN_HELP, TOKEN_SEND_ITEMS, authFormFrom, authSummary, buildAuthBody, rowField, usesHeaders, usesLogin, validateAuthForm,
} from '~/utils/dastAuth'
import type { Codebase, DastAuth, LoginCheckResult } from '~/types/api'

// "Authentication" panel of a URL target: None / Login form / Fixed header(s) / Login form + headers.
// Credentials are write-only. Once saved the panel shows "Credential saved" with Replace and Remove and never
// the values; Replace opens the form with the secret inputs empty (a blank secret keeps the stored value).
const props = defineProps<{ codebase: Codebase }>()
const emit = defineEmits<{ saved: [DastAuth | null] }>()

const auth = useAuth()
const api = useApi()
const toast = useNotify()

const allowed = computed(() => hasDastAccess(auth.user) && props.codebase.target_type === 'url')
// The saved (non-secret) description: follows the parent's codebase and is updated at once by our own PUT / DELETE.
const saved = ref<DastAuth | null>(props.codebase.dast_auth ?? null)
watch(() => props.codebase.dast_auth, (v) => { saved.value = v ?? null })
const hasSaved = computed(() => !!saved.value && saved.value.type !== 'none')
const confirmed = computed(() => props.codebase.dast?.status === 'confirmed')

const editing = ref(!hasSaved.value)
const form = reactive(authFormFrom(saved.value, props.codebase.base_url))
const busy = ref(false)
const removeOpen = ref(false)
const testing = ref(false)
const result = ref<LoginCheckResult | null>(null)
const testError = ref<string | null>(null)

function clientErrors(): Record<string, string> {
  if (form.type === 'none') return hasSaved.value ? {} : { type: 'Choose an authentication type to save.' }
  return validateAuthForm(form, props.codebase.base_url, saved.value)
}

// Field names are the API's field paths (login.url, login.csrf.name, headers.<name>, ...), so server errors land on the same fields.
const fe = useFormErrors({ validate: clientErrors, labels: { total: 'Authentication settings', login: 'Login form' } })
// Typing in a field clears its error. Rows are keyed like their fields (headers.<name>).
fe.autoClear(() => {
  const l = form.login
  const out: Record<string, unknown> = {
    type: form.type, 'login.url': l.url, 'login.method': l.method, 'login.body_format': l.body_format, 'login.username_field': l.username_field,
    'login.password_field': l.password_field, 'login.username': l.username, 'login.password': l.password, 'login.csrf.source': l.csrf_source,
    'login.csrf.name': l.csrf_name, 'login.csrf.send_as': l.csrf_send_as, 'login.csrf.header_name': l.csrf_header_name, 'login.success.statuses': l.success_statuses,
    'login.success.cookie_set': l.success_cookie_set, 'login.success.body_contains': l.success_body_contains,
    'login.success.body_not_contains': l.success_body_not_contains, 'login.success.redirect_not_to': l.success_redirect_not_to,
    'login.token.from': l.token_from, 'login.token.path': l.token_path, 'login.token.send_as': l.token_send_mode, 'login.token.header_name': l.token_header_name,
    'login.token.prefix': l.token_prefix, 'login.token.cookie_name': l.token_cookie_name, 'login.success.json_path_exists': l.success_json_exists,
    'login.success.json_path_equals.path': l.success_json_equals_path, 'login.success.json_path_equals.value': l.success_json_equals_value,
    'login.extra_fields': l.extra.length, headers: form.headers.length, cookies: form.cookies.length,
  }
  for (const [prefix, list] of [['login.extra_fields', l.extra], ['headers', form.headers], ['cookies', form.cookies]] as const) {
    for (const r of list) out[rowField(prefix, r)] = r.value
  }
  return out
})

// Another type shows other fields: errors of the old layout no longer apply.
watch(() => form.type, () => fe.clearAll())

function resetForm(type?: DastAuth['type']) {
  Object.assign(form, authFormFrom(saved.value, props.codebase.base_url, type))
  fe.reset()
}

function startReplace() {
  resetForm()
  editing.value = true
  result.value = null
}

function cancel() {
  resetForm()
  editing.value = false
}

const showLogin = computed(() => usesLogin(form.type))
const showHeaders = computed(() => usesHeaders(form.type))
const removing = computed(() => form.type === 'none' && hasSaved.value)
const baseOrigin = computed(() => { try { return new URL(props.codebase.base_url ?? '').origin } catch { return '' } })

async function save() {
  if (busy.value) return
  if (removing.value) { removeOpen.value = true; return }
  if (!fe.check()) return
  busy.value = true
  try {
    const res = await api.dastAuth.put(props.codebase.id, buildAuthBody(form))
    toast.success('Authentication saved. The credentials are stored encrypted.')
    // Drop every typed secret immediately; the saved view never shows them.
    form.login.password = ''
    for (const r of [...form.login.extra, ...form.headers, ...form.cookies]) r.value = ''
    saved.value = res
    editing.value = false
    result.value = null
    emit('saved', res)
  } catch (e) {
    fe.fromServer(e)
  } finally {
    busy.value = false
  }
}

async function remove() {
  busy.value = true
  try {
    await api.dastAuth.remove(props.codebase.id)
    toast.success('Authentication removed.')
    removeOpen.value = false
    result.value = null
    saved.value = null
    resetForm()
    editing.value = true
    emit('saved', null)
  } catch (e) {
    fe.formError.value = friendlyError(e).message
    removeOpen.value = false
  } finally {
    busy.value = false
  }
}

async function testLogin() {
  testing.value = true
  result.value = null
  testError.value = null
  try {
    result.value = await api.dastAuth.test(props.codebase.id)
  } catch (e) {
    testError.value = friendlyError(e).message
  } finally {
    testing.value = false
  }
}

// Follow the engine's defaults for the CSRF token: html_input is sent as a field, a cookie or header token as a header.
function csrfSourceChanged(src: unknown) { form.login.csrf_send_as = src === 'html_input' ? 'field' : 'header' }

// The usual prefix of an Authorization header is "Bearer "; a custom header usually carries the bare token.
function tokenModeChanged(mode: unknown) {
  if (mode === 'authorization') form.login.token_prefix = 'Bearer '
  else if (mode === 'header' && form.login.token_prefix === 'Bearer ') form.login.token_prefix = ''
}

// The saved settings changed elsewhere (another tab, base URL change removed them): follow.
watch(() => [saved.value?.type, saved.value?.updated_at], () => {
  resetForm()
  if (!hasSaved.value) editing.value = true
})
</script>

<template>
  <UCard v-if="allowed" aria-labelledby="auth-h" data-testid="dast-auth" role="region">
    <h2 id="auth-h" class="mb-1 text-base">Authentication</h2>
    <p class="mb-1 text-muted">Let the scan log in before it checks the site. Use a test account with the minimum rights needed. Credentials are stored encrypted and are only sent to the target host.</p>
    <p class="mb-3 text-sm text-muted" data-testid="auth-limits">{{ AUTH_LIMITS_NOTE }}</p>

    <!-- Saved: never shows a value. -->
    <div v-if="hasSaved && !editing" class="rounded-md border border-default p-3" data-testid="auth-saved">
      <p class="flex flex-wrap items-center gap-2">
        <UBadge color="success" variant="subtle" icon="i-lucide-lock" data-testid="credential-saved">Credential saved</UBadge>
        <span class="font-medium" data-testid="auth-type">{{ AUTH_TYPE_LABEL[saved!.type] }}</span>
      </p>
      <p class="mt-2 break-words font-mono text-xs text-muted" data-testid="auth-summary">{{ authSummary(saved!) }}</p>
      <p v-if="saved!.updated_at" class="mt-1 text-xs text-muted">Updated <LocalTime :value="saved!.updated_at" /><template v-if="saved!.updated_by"> by {{ displayUser(saved!.updated_by) }}</template>. The values are write-only and cannot be shown.</p>
      <div class="mt-3 flex flex-wrap gap-2">
        <UButton color="neutral" variant="outline" icon="i-lucide-refresh-cw" :disabled="busy" data-testid="replace-auth" @click="startReplace">Replace</UButton>
        <UButton color="error" variant="outline" icon="i-lucide-trash-2" :disabled="busy" data-testid="remove-auth" @click="removeOpen = true;">Remove</UButton>
        <UButton v-if="usesLogin(saved!.type)" icon="i-lucide-log-in" :loading="testing" :disabled="!confirmed || busy" data-testid="test-login" @click="testLogin">Test login</UButton>
      </div>
      <p v-if="!usesLogin(saved!.type)" class="mt-2 text-sm text-muted" data-testid="no-login-test">Fixed headers and cookies have no login step to test. They are sent with every request of the scan.</p>
      <p v-else-if="!confirmed" class="mt-2 text-sm text-warning" data-testid="test-hint">{{ TARGET_NOT_CONFIRMED_HINT }} The login test needs a confirmed target.</p>
      <div aria-live="polite">
        <UAlert
          v-if="result" class="mt-3" :color="result.ok ? 'success' : 'error'" variant="subtle" :icon="result.ok ? 'i-lucide-circle-check' : 'i-lucide-circle-x'"
          :title="result.ok ? 'Login succeeded' : 'Login failed'" :description="result.message" data-testid="login-check-result"
        />
        <p v-if="testError" class="mt-2 text-sm font-medium text-error" role="alert" data-testid="login-check-error">{{ testError }}</p>
      </div>
    </div>

    <form v-else novalidate data-testid="auth-form" @submit.prevent="save">
      <FormErrorSummary class="mb-4" error-testid="auth-error" />
      <fieldset :disabled="busy" class="space-y-4">
        <AppField name="type" label="Authentication type" required>
          <URadioGroup v-model="form.type" orientation="horizontal" :items="AUTH_TYPE_ITEMS" data-testid="auth-type-select" />
        </AppField>
        <UAlert v-if="removing" color="warning" variant="subtle" icon="i-lucide-triangle-alert" description="Saving with “None” removes the saved credentials. Scans will no longer log in." />
        <UAlert v-if="hasSaved && !removing" color="info" variant="subtle" icon="i-lucide-info" description="Leave a password, header value or cookie value empty to keep the saved one. Typing a value replaces it." />

        <template v-if="showLogin">
          <h3 class="text-sm font-medium text-highlighted">Login form</h3>
          <div class="grid gap-4 sm:grid-cols-2">
            <AppField class="sm:col-span-2" label="Login URL" name="login.url" required :help="`Same origin as the base URL${baseOrigin ? ` (${baseOrigin})` : ''}.`">
              <UInput id="auth-login-url" v-model="form.login.url" class="w-full font-mono" autocomplete="off" spellcheck="false" />
            </AppField>
            <AppField label="Method" name="login.method" required>
              <USelect id="auth-method" v-model="form.login.method" :items="['POST', 'PUT', 'PATCH']" class="w-full" />
            </AppField>
            <AppField label="Body format" name="login.body_format" required>
              <USelect id="auth-format" v-model="form.login.body_format" :items="[{ label: 'Form (urlencoded)', value: 'form' }, { label: 'JSON', value: 'json' }]" class="w-full" />
            </AppField>
            <AppField label="Username field" name="login.username_field" required help="The name of the form field that receives the username.">
              <UInput id="auth-ufield" v-model="form.login.username_field" class="w-full font-mono" autocomplete="off" spellcheck="false" />
            </AppField>
            <AppField label="Password field" name="login.password_field" required help="The name of the form field that receives the password.">
              <UInput id="auth-pfield" v-model="form.login.password_field" class="w-full font-mono" autocomplete="off" spellcheck="false" />
            </AppField>
            <AppField label="Username" name="login.username" required>
              <UInput id="auth-username" v-model="form.login.username" class="w-full" autocomplete="off" spellcheck="false" />
            </AppField>
            <AppField label="Password" name="login.password" required help="Write-only. Stored encrypted and never shown again.">
              <UInput id="auth-password" v-model="form.login.password" type="password" class="w-full" autocomplete="new-password" :placeholder="hasSaved && saved!.type !== 'header' ? 'Saved (leave blank to keep)' : ''" data-testid="auth-password" />
            </AppField>
          </div>

          <AppField label="Extra form fields" name="login.extra_fields" :hint="`Up to ${MAX_EXTRA_FIELDS}`" help="Fixed fields sent with the login, for example a tenant or role. Values are write-only.">
            <PairListEditor v-model="form.login.extra" label="Extra field" field-prefix="login.extra_fields" name-placeholder="field name" add-label="Add field" :max="MAX_EXTRA_FIELDS" testid="auth-extra" allow-empty-value />
          </AppField>

          <div class="rounded-md border border-default p-3">
            <UCheckbox v-model="form.login.csrf_enabled" label="The login form has a CSRF token" data-testid="auth-csrf-toggle" />
            <div v-if="form.login.csrf_enabled" class="mt-3 grid gap-4 sm:grid-cols-2">
              <AppField label="Read it from" name="login.csrf.source" required>
                <USelect v-model="form.login.csrf_source" :items="[{ label: 'HTML input', value: 'html_input' }, { label: 'Cookie', value: 'cookie' }, { label: 'Response header', value: 'header' }]" class="w-full" @update:model-value="csrfSourceChanged" />
              </AppField>
              <AppField label="Name" name="login.csrf.name" required help="Input name, cookie name or header name.">
                <UInput v-model="form.login.csrf_name" class="w-full font-mono" placeholder="_csrf" autocomplete="off" spellcheck="false" />
              </AppField>
              <AppField label="Send it as" name="login.csrf.send_as" required>
                <USelect v-model="form.login.csrf_send_as" :items="[{ label: 'Form / JSON field', value: 'field' }, { label: 'Request header', value: 'header' }]" class="w-full" />
              </AppField>
              <AppField v-if="form.login.csrf_send_as === 'header'" label="Header name" name="login.csrf.header_name" help="Empty means X-CSRF-Token.">
                <UInput v-model="form.login.csrf_header_name" class="w-full font-mono" placeholder="X-CSRF-Token" autocomplete="off" spellcheck="false" />
              </AppField>
            </div>
          </div>

          <div class="rounded-md border border-default p-3" data-testid="auth-token-section">
            <UCheckbox v-model="form.login.token_enabled" label="Token in login response" data-testid="auth-token-toggle" />
            <p class="mt-1 text-sm text-muted" data-testid="auth-token-help">{{ TOKEN_HELP }}</p>
            <div v-if="form.login.token_enabled" class="mt-3 grid gap-4 sm:grid-cols-2">
              <AppField label="Source" name="login.token.from" required>
                <USelect v-model="form.login.token_from" :items="TOKEN_FROM_ITEMS" class="w-full" data-testid="auth-token-from" />
              </AppField>
              <AppField :label="form.login.token_from === 'json' ? 'Path' : 'Header name'" name="login.token.path" required :help="form.login.token_from === 'json' ? 'Dotted path to the token in the JSON response, for example data.access_token or items[0].token.' : 'The response header that carries the token.'">
                <UInput v-model="form.login.token_path" class="w-full font-mono" :placeholder="form.login.token_from === 'json' ? 'data.access_token' : 'X-Auth-Token'" autocomplete="off" spellcheck="false" data-testid="auth-token-path" />
              </AppField>
              <AppField label="Send as" name="login.token.send_as" required help="How the token is sent with every later request to the target.">
                <USelect v-model="form.login.token_send_mode" :items="TOKEN_SEND_ITEMS" class="w-full" data-testid="auth-token-send" @update:model-value="tokenModeChanged" />
              </AppField>
              <AppField v-if="form.login.token_send_mode === 'header'" label="Header name" name="login.token.header_name" required>
                <UInput v-model="form.login.token_header_name" class="w-full font-mono" placeholder="X-Auth-Token" autocomplete="off" spellcheck="false" data-testid="auth-token-header" />
              </AppField>
              <AppField v-if="form.login.token_send_mode !== 'cookie'" label="Prefix" name="login.token.prefix" hint="Optional" help="Put before the token, for example “Bearer ” (with the trailing space). Leave empty to send the bare token.">
                <UInput v-model="form.login.token_prefix" class="w-full font-mono" placeholder="Bearer " autocomplete="off" spellcheck="false" data-testid="auth-token-prefix" />
              </AppField>
              <AppField v-else label="Cookie name" name="login.token.cookie_name" required>
                <UInput v-model="form.login.token_cookie_name" class="w-full font-mono" placeholder="token" autocomplete="off" spellcheck="false" data-testid="auth-token-cookie" />
              </AppField>
              <p class="text-xs text-muted sm:col-span-2" data-testid="auth-token-example">{{ TOKEN_EXAMPLE }}</p>
            </div>
          </div>

          <fieldset class="rounded-md border border-default p-3">
            <legend class="px-1 text-sm font-medium text-highlighted">Success indicator <span class="font-normal text-muted">(optional)</span></legend>
            <div class="grid gap-4 sm:grid-cols-2">
              <AppField label="Status codes" name="login.success.statuses" hint="Optional" help="Comma separated, for example 200, 302.">
                <UInput v-model="form.login.success_statuses" class="w-full font-mono" autocomplete="off" />
              </AppField>
              <AppField label="Cookie set" name="login.success.cookie_set" hint="Optional" help="A cookie that appears after login.">
                <UInput v-model="form.login.success_cookie_set" class="w-full font-mono" autocomplete="off" spellcheck="false" />
              </AppField>
              <AppField label="Body contains" name="login.success.body_contains" hint="Optional">
                <UInput v-model="form.login.success_body_contains" class="w-full" autocomplete="off" />
              </AppField>
              <AppField label="Body does not contain" name="login.success.body_not_contains" hint="Optional">
                <UInput v-model="form.login.success_body_not_contains" class="w-full" autocomplete="off" />
              </AppField>
              <AppField class="sm:col-span-2" label="Redirect not to" name="login.success.redirect_not_to" hint="Optional" help="A failed login usually redirects back here, for example /login.">
                <UInput v-model="form.login.success_redirect_not_to" class="w-full font-mono" placeholder="/login" autocomplete="off" spellcheck="false" />
              </AppField>
              <AppField label="JSON path exists" name="login.success.json_path_exists" hint="Optional" help="A path that must exist in the JSON response, for example data.access_token.">
                <UInput v-model="form.login.success_json_exists" class="w-full font-mono" placeholder="data.access_token" autocomplete="off" spellcheck="false" data-testid="auth-json-exists" />
              </AppField>
              <div class="grid grid-cols-2 gap-2">
                <AppField label="JSON path equals" name="login.success.json_path_equals.path" hint="Optional" help="Path in the JSON response.">
                  <UInput v-model="form.login.success_json_equals_path" class="w-full font-mono" placeholder="status" autocomplete="off" spellcheck="false" data-testid="auth-json-equals-path" />
                </AppField>
                <AppField label="Equals value" name="login.success.json_path_equals.value" help="For example ok or true.">
                  <UInput v-model="form.login.success_json_equals_value" class="w-full" placeholder="ok" autocomplete="off" data-testid="auth-json-equals-value" />
                </AppField>
              </div>
            </div>
          </fieldset>
        </template>

        <template v-if="showHeaders">
          <h3 class="text-sm font-medium text-highlighted">Fixed headers and cookies</h3>
          <AppField label="Headers" name="headers" required :hint="`Up to ${MAX_HEADERS}`" help="For example Authorization: Bearer … or X-Api-Key. Add at least one header or cookie. Values are write-only.">
            <PairListEditor v-model="form.headers" label="Header" field-prefix="headers" name-placeholder="Authorization" value-placeholder="Bearer …" add-label="Add header" :max="MAX_HEADERS" testid="auth-headers" />
          </AppField>
          <AppField label="Cookies" name="cookies" :hint="`Up to ${MAX_COOKIES}`" help="Sent with every request to the target. Values are write-only.">
            <PairListEditor v-model="form.cookies" label="Cookie" field-prefix="cookies" name-placeholder="session" add-label="Add cookie" :max="MAX_COOKIES" testid="auth-cookies" />
          </AppField>
        </template>
      </fieldset>

      <div class="mt-4 flex flex-wrap gap-2">
        <UButton type="submit" :loading="busy" :color="removing ? 'error' : 'primary'" data-testid="save-auth">{{ busy ? 'Saving…' : (removing ? 'Remove authentication' : 'Save authentication') }}</UButton>
        <UButton v-if="hasSaved" color="neutral" variant="outline" :disabled="busy" data-testid="cancel-auth" @click="cancel">Cancel</UButton>
      </div>
    </form>

    <ModalDialog :open="removeOpen" title="Remove authentication" :busy="busy" @close="removeOpen = false">
      <p>Remove the saved credentials of <strong>{{ codebase.name }}</strong>? Scans, including scheduled ones, will no longer log in. The values cannot be recovered.</p>
      <template #footer>
        <UButton color="neutral" variant="outline" :disabled="busy" @click="removeOpen = false;">Cancel</UButton>
        <UButton color="error" :loading="busy" data-autofocus data-testid="confirm-remove-auth" @click="remove">Remove</UButton>
      </template>
    </ModalDialog>
  </UCard>
</template>
