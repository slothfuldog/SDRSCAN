<script setup lang="ts">
import { hasDastAccess } from '~/utils/permissions'
import { ACTIVE_SCANNING_RISK_NOTE, openapiSpecUrlIssue } from '~/utils/dastAuth'
import { displayUser } from '~/utils/format'
import { friendlyError } from '~/utils/errors'
import type { Codebase } from '~/types/api'

// "Active scanning" panel of a URL target: a SEPARATE, stricter authorization on top of the basic DAST
// target confirmation above it. Sends SQL injection, XSS, open redirect and header-injection test
// payloads; see ACTIVE_SCANNING_RISK_NOTE for the full warning shown here and in the dialog.
const props = defineProps<{ codebase: Codebase }>()
const emit = defineEmits<{ saved: [] }>()

const auth = useAuth()
const api = useApi()
const toast = useNotify()

const allowed = computed(() => hasDastAccess(auth.user) && props.codebase.target_type === 'url')
const dastActive = computed(() => props.codebase.dast_active)
const authorized = computed(() => dastActive.value?.authorized === true)

const authorizeOpen = ref(false)
const revoking = ref(false)

async function onAuthorized() {
  authorizeOpen.value = false
  toast.success('Active scanning authorized for this target.')
  emit('saved')
}

async function revoke() {
  revoking.value = true
  try {
    await api.codebases.revokeActiveScanning(props.codebase.id)
    toast.success('Active scanning authorization revoked.')
    emit('saved')
  } catch (e) {
    toast.error(friendlyError(e).message)
  } finally {
    revoking.value = false
  }
}

// OpenAPI/Swagger spec URL: optional, independent of the authorization itself.
const specUrl = ref(dastActive.value?.openapi_spec_url ?? '')
watch(() => dastActive.value?.openapi_spec_url, (v) => { specUrl.value = v ?? '' })
const specDirty = computed(() => specUrl.value.trim() !== (dastActive.value?.openapi_spec_url ?? ''))
const specBusy = ref(false)

const fe = useFormErrors({
  aliases: { dast_openapi_spec_url: 'spec_url' },
  labels: { spec_url: 'OpenAPI/Swagger spec URL' },
  validate: () => {
    const m = openapiSpecUrlIssue(specUrl.value, props.codebase.base_url)
    return m ? { spec_url: m } : {}
  },
})
fe.autoClear(() => ({ spec_url: specUrl.value }))

async function saveSpec() {
  if (specBusy.value || !fe.check()) return
  specBusy.value = true
  try {
    await api.codebases.patch(props.codebase.id, { dast_openapi_spec_url: specUrl.value.trim() || null })
    toast.success('OpenAPI/Swagger spec setting saved.')
    emit('saved')
  } catch (e) {
    fe.fromServer(e, { fallback: 'spec_url' })
  } finally {
    specBusy.value = false
  }
}
</script>

<template>
  <UCard v-if="allowed" id="active-scanning" aria-labelledby="active-scanning-h" data-testid="active-scanning" role="region" :ui="{ root: 'ring-warning/40' }">
    <h2 id="active-scanning-h" class="mb-1 flex items-center gap-2 text-base">
      <UIcon name="i-lucide-triangle-alert" class="text-warning" aria-hidden="true" />
      Active scanning
    </h2>
    <p class="mb-3 text-muted">{{ ACTIVE_SCANNING_RISK_NOTE }}</p>

    <template v-if="authorized">
      <p class="flex flex-wrap items-center gap-2" data-testid="active-scanning-status">
        <UBadge color="warning" variant="subtle" icon="i-lucide-shield-alert">Active scanning authorized</UBadge>
      </p>
      <dl class="mt-3 grid grid-cols-[10rem_1fr] gap-y-1">
        <dt class="text-muted">Authorized by</dt><dd>{{ displayUser(dastActive?.authorized_by) }}</dd>
        <dt class="text-muted">Authorized on</dt><dd><LocalTime :value="dastActive?.authorized_at" /></dd>
      </dl>
      <div class="mt-3">
        <UButton color="warning" variant="outline" icon="i-lucide-shield-off" :loading="revoking" data-testid="revoke-active-scanning" @click="revoke">
          {{ revoking ? 'Revoking…' : 'Revoke' }}
        </UButton>
      </div>
    </template>
    <template v-else>
      <p class="mb-3 text-muted">Not authorized: DAST scans on this target can only ever run passively.</p>
      <UButton color="warning" icon="i-lucide-shield-alert" data-testid="authorize-active-scanning" @click="authorizeOpen = true;">Authorize active scanning</UButton>
    </template>

    <form novalidate class="mt-5 border-t border-default pt-4" data-testid="openapi-spec-form" @submit.prevent="saveSpec">
      <FormErrorSummary class="mb-3" error-testid="openapi-spec-error" />
      <AppField
        label="OpenAPI/Swagger spec URL" name="spec_url" :disabled="specBusy"
        help="Optional. When set, active scanning also exercises the API operations this spec describes. Leave empty to rely on auto-discovery during the crawl only."
      >
        <UInput id="openapi-spec-url" v-model="specUrl" class="w-full font-mono" placeholder="https://shop.example.com/openapi.json" autocomplete="off" spellcheck="false" :disabled="specBusy" />
      </AppField>
      <div class="mt-3">
        <UButton type="submit" color="neutral" variant="outline" :disabled="!specDirty" :loading="specBusy" data-testid="save-openapi-spec">
          {{ specBusy ? 'Saving…' : 'Save' }}
        </UButton>
      </div>
    </form>

    <AuthorizeActiveScanningDialog :open="authorizeOpen" :codebase="codebase" @close="authorizeOpen = false" @authorized="onAuthorized" />
  </UCard>
</template>
