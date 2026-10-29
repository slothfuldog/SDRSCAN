<script setup lang="ts">
import { allowedTargetTypes, canEditUrlTarget } from '~/utils/permissions'
import { validateBaseUrl, validateBranch, validateName, validateRepoUrl, validateSubdirectory } from '~/utils/validators'
import type { Codebase, CreateCodebaseBody, GitAuthKind, PatchCodebaseBody, TargetType } from '~/types/api'

// Add / edit a Codebase. Repo: URL, branch, subdirectory, git credential (write-only). URL: base URL (DAST).
// The schedule is managed in its own panel (PUT /codebases/{id}/schedule), not through this form.
const props = defineProps<{ mode: 'create' | 'edit', projectId?: number, codebase?: Codebase | null }>()
const emit = defineEmits<{ saved: [Codebase] }>()

const auth = useAuth()
const api = useApi()

const targetTypes = computed(() => allowedTargetTypes(auth.user))
const typeItems = computed(() => [
  { label: 'Repository (SAST)', value: 'repo' },
  ...(targetTypes.value.includes('url') ? [{ label: 'URL (DAST)', value: 'url' }] : []),
])
const authItems = [
  { label: 'None (public repository)', value: 'none' },
  { label: 'HTTPS access token', value: 'https_token' },
  { label: 'SSH private key', value: 'ssh_key' },
]

const state = reactive({
  name: props.codebase?.name ?? '',
  target_type: (props.codebase?.target_type ?? 'repo') as TargetType,
  language: props.codebase?.language ?? 'php',
  repo_url: props.codebase?.repo_url ?? '',
  branch: props.codebase?.branch ?? 'main',
  subdirectory: props.codebase?.subdirectory ?? '',
  git_auth_kind: (props.codebase?.git_auth_kind ?? 'none') as GitAuthKind,
  git_username: props.codebase?.git_username ?? '',
  git_secret: '',
  base_url: props.codebase?.base_url ?? '',
  dast_max_rps: props.codebase?.dast_max_rps ?? 5,
})
const busy = ref(false)
const replaceCredential = ref(false)

const isUrl = computed(() => state.target_type === 'url')
const isEdit = computed(() => props.mode === 'edit')
// Admins and Members with DAST access may change a URL target's base URL and rate limit.
const urlEditable = computed(() => !isEdit.value || canEditUrlTarget(auth.user))
const baseUrlChanged = computed(() => isEdit.value && isUrl.value && state.base_url.trim() !== (props.codebase?.base_url ?? ''))
const hasStoredCredential = computed(() => !!props.codebase?.has_credential && props.codebase.git_auth_kind === state.git_auth_kind && state.git_auth_kind !== 'none')
const showSecretInput = computed(() => state.git_auth_kind !== 'none' && (!hasStoredCredential.value || replaceCredential.value))

/** Checks every field of the visible form at once. */
function validate(): Record<string, string> {
  const errors: Record<string, string> = {}
  const add = (name: string, message: string | null) => { if (message && !(name in errors)) errors[name] = message }
  const s = state
  add('name', validateName(s.name))
  if (s.language.trim().length > 50) add('language', 'Language must be at most 50 characters.')
  if (s.target_type === 'url') {
    add('base_url', validateBaseUrl(s.base_url))
    if (isEdit.value && (!Number.isInteger(Number(s.dast_max_rps)) || s.dast_max_rps < 1 || s.dast_max_rps > 100)) add('dast_max_rps', 'Use a whole number from 1 to 100.')
  } else {
    add('repo_url', validateRepoUrl(s.repo_url))
    add('branch', validateBranch(s.branch))
    add('subdirectory', validateSubdirectory(s.subdirectory))
    if (s.git_auth_kind === 'https_token' && !s.git_username.trim()) add('git_username', 'Username is required for token authentication.')
    if (s.git_auth_kind !== 'none' && showSecretInput.value && !s.git_secret) add('git_secret', s.git_auth_kind === 'ssh_key' ? 'Private key is required: paste the key.' : 'Access token is required: paste the token.')
  }
  return errors
}

const fe = useFormErrors({ validate })
fe.autoClear(() => ({ ...state, replaceCredential: replaceCredential.value }))
// The credential fields depend on the authentication kind: their old errors no longer apply.
watch(() => state.git_auth_kind, () => { fe.clear('git_secret'); fe.clear('git_username') })

function buildCreate(): CreateCodebaseBody {
  const base: CreateCodebaseBody = { name: state.name.trim(), target_type: state.target_type, language: state.language.trim() }
  if (isUrl.value) return { ...base, base_url: state.base_url.trim() }
  return {
    ...base,
    repo_url: state.repo_url.trim(),
    branch: state.branch.trim() || 'main',
    subdirectory: state.subdirectory.trim(),
    git_auth_kind: state.git_auth_kind,
    ...(state.git_auth_kind === 'https_token' ? { git_username: state.git_username.trim() } : {}),
    ...(state.git_auth_kind !== 'none' && state.git_secret ? { git_secret: state.git_secret } : {}),
  }
}

function buildPatch(): PatchCodebaseBody {
  const cb = props.codebase!
  const body: PatchCodebaseBody = {}
  if (state.name.trim() !== cb.name) body.name = state.name.trim()
  if (state.language.trim() !== cb.language) body.language = state.language.trim()
  if (isUrl.value) {
    if (state.base_url.trim() !== cb.base_url) body.base_url = state.base_url.trim()
    if (Number(state.dast_max_rps) !== (cb.dast_max_rps ?? 5)) body.dast_max_rps = Number(state.dast_max_rps)
    return body
  }
  if (state.repo_url.trim() !== cb.repo_url) body.repo_url = state.repo_url.trim()
  if ((state.branch.trim() || 'main') !== (cb.branch ?? 'main')) body.branch = state.branch.trim() || 'main'
  if (state.subdirectory.trim() !== (cb.subdirectory ?? '')) body.subdirectory = state.subdirectory.trim()
  if (state.git_auth_kind !== (cb.git_auth_kind ?? 'none')) body.git_auth_kind = state.git_auth_kind
  if (state.git_auth_kind === 'https_token' && state.git_username.trim() !== (cb.git_username ?? '')) body.git_username = state.git_username.trim()
  if (state.git_secret) body.git_secret = state.git_secret
  return body
}

async function submit() {
  if (busy.value || !fe.check()) return
  busy.value = true
  try {
    let saved: Codebase
    if (isEdit.value) {
      const patch = buildPatch()
      saved = Object.keys(patch).length ? await api.codebases.patch(props.codebase!.id, patch) : props.codebase!
    } else {
      saved = await api.codebases.create(props.projectId!, buildCreate())
    }
    state.git_secret = ''
    replaceCredential.value = false
    emit('saved', saved)
  } catch (e) {
    fe.fromServer(e, { privateNetworkField: isUrl.value ? 'base_url' : 'repo_url', byCode: { name_taken: 'name' } })
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <UForm :loading-auto="false" :state="state" novalidate class="space-y-5" data-testid="codebase-form" @submit="submit">
    <FormErrorSummary />
    <div class="grid gap-4 sm:grid-cols-2">
      <AppField name="name" label="Name" required help="Unique within the project. CI refers to the codebase by this name.">
        <UInput id="cb-name" v-model="state.name" maxlength="100" class="w-full" :disabled="busy" />
      </AppField>
      <AppField v-if="!isUrl" name="language" label="Language" hint="Optional">
        <UInput id="cb-lang" v-model="state.language" placeholder="php" class="w-full" :disabled="busy" />
      </AppField>
    </div>

    <AppField v-if="!isEdit" name="target_type" label="Target type" required :help="targetTypes.includes('url') ? undefined : 'URL targets (DAST) need DAST access. Ask an Admin if you need it.'">
      <URadioGroup v-model="state.target_type" :items="typeItems" orientation="horizontal" :disabled="busy" />
    </AppField>

    <template v-if="!isUrl">
      <div class="grid gap-4 sm:grid-cols-2">
        <AppField name="repo_url" label="Repository URL" required help="https://host/path, ssh://host/path or git@host:path." class="sm:col-span-2">
          <UInput id="cb-repo" v-model="state.repo_url" class="w-full font-mono" placeholder="https://git.example.com/team/app.git" autocomplete="off" spellcheck="false" :disabled="busy" />
        </AppField>
        <AppField name="branch" label="Branch" hint="Optional" help="Empty means main.">
          <UInput id="cb-branch" v-model="state.branch" class="w-full font-mono" placeholder="main" :disabled="busy" />
        </AppField>
        <AppField name="subdirectory" label="Subdirectory" hint="Optional" help="For monorepos: register one codebase per subdirectory.">
          <UInput id="cb-subdir" v-model="state.subdirectory" class="w-full font-mono" placeholder="apps/storefront" :disabled="busy" />
        </AppField>
      </div>

      <fieldset class="rounded-md border border-default p-4" :disabled="busy">
        <legend class="px-1 text-sm font-medium text-highlighted">Git credential</legend>
        <div class="grid gap-4 sm:grid-cols-2">
          <AppField name="git_auth_kind" label="Authentication" required>
            <USelect id="cb-auth" v-model="state.git_auth_kind" :items="authItems" class="w-full" />
          </AppField>
          <AppField v-if="state.git_auth_kind === 'https_token'" name="git_username" label="Username" required>
            <UInput id="cb-guser" v-model="state.git_username" class="w-full" placeholder="x-access-token" autocomplete="off" />
          </AppField>
        </div>
        <div v-if="state.git_auth_kind !== 'none'" class="mt-3">
          <div v-if="hasStoredCredential && !replaceCredential" class="flex flex-wrap items-center gap-2" data-testid="credential-saved">
            <UBadge color="success" variant="subtle" icon="i-lucide-lock">Credential saved</UBadge>
            <UButton color="neutral" variant="outline" size="xs" @click="replaceCredential = true;">Replace credential</UButton>
          </div>
          <AppField v-else name="git_secret" :label="state.git_auth_kind === 'ssh_key' ? 'Private key' : 'Access token'" required help="Write-only. It is stored encrypted and never shown again.">
            <UTextarea v-if="state.git_auth_kind === 'ssh_key'" id="cb-secret" v-model="state.git_secret" :rows="4" class="w-full font-mono" autocomplete="off" spellcheck="false" />
            <UInput v-else id="cb-secret" v-model="state.git_secret" type="password" class="w-full" autocomplete="new-password" />
          </AppField>
        </div>
      </fieldset>
    </template>

    <template v-else>
      <div class="grid gap-4 sm:grid-cols-2">
        <AppField name="base_url" label="Base URL" required help="Only scan systems you are authorized to test. An Admin must confirm authorization before the first scan." class="sm:col-span-2">
          <UInput id="cb-base" v-model="state.base_url" class="w-full font-mono" placeholder="https://shop.example.com" autocomplete="off" spellcheck="false" :disabled="busy || !urlEditable" />
          <UAlert v-if="baseUrlChanged" class="mt-2" color="warning" variant="subtle" role="status" description="Changing the base URL resets the target to “Pending confirmation”. An Admin must confirm authorization again." />
        </AppField>
        <AppField v-if="isEdit" name="dast_max_rps" label="Max requests per second" required help="Whole number from 1 to 100.">
          <UInput id="cb-rps" v-model.number="state.dast_max_rps" type="number" :min="1" :max="100" class="w-full" :disabled="busy || !urlEditable" />
        </AppField>
      </div>
      <UAlert v-if="!urlEditable" color="info" variant="subtle" description="You need DAST access to change a URL target. Ask an Admin." />
    </template>

    <div class="flex flex-wrap gap-2">
      <UButton type="submit" :loading="busy" :disabled="isUrl && !urlEditable">{{ busy ? 'Saving…' : (isEdit ? 'Save changes' : 'Add codebase') }}</UButton>
      <slot name="actions" />
    </div>
  </UForm>
</template>
