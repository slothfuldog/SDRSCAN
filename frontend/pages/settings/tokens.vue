<script setup lang="ts">
import type { TableColumn } from '@nuxt/ui'
import { friendlyError } from '~/utils/errors'
import { ingestCurlExample } from '~/utils/curl'
import { validateName } from '~/utils/validators'
import type { CreatedIngestToken, IngestToken } from '~/types/api'

useHead({ title: 'Ingest tokens · SDRScan' })

const auth = useAuth()
const api = useApi()
const toast = useNotify()
const ALL = '__all__'

const { data, error, pending, reload } = useLoad(async () => (auth.isAdmin ? (await api.tokens.list({ page: 1, page_size: 200 })).items : undefined))
const { data: projects } = useLoad(async () => (auth.isAdmin ? (await api.projects.list({ page: 1, page_size: 200 })).items : []))
const projectItems = computed(() => [{ label: 'All projects', value: ALL }, ...(projects.value ?? []).map(p => ({ label: p.name, value: String(p.id) }))])

const columns: TableColumn<IngestToken>[] = [
  { id: 'name', header: 'Name' },
  { id: 'prefix', header: 'Prefix' },
  { id: 'project', header: 'Project' },
  { id: 'used', header: 'Last used' },
  { id: 'status', header: 'Status' },
  { id: 'actions', header: () => h('span', { class: 'sr-only' }, 'Actions') },
]

const createOpen = ref(false)
const state = reactive({ name: '', project: ALL })
const busy = ref(false)
const created = ref<CreatedIngestToken | null>(null)
const revoking = ref<IngestToken | null>(null)
const revokeBusy = ref(false)

const origin = computed(() => (import.meta.client ? window.location.origin : ''))
const fe = useFormErrors({
  aliases: { project_id: 'project' },
  validate: () => {
    const m = validateName(state.name, 'name')
    return m ? { name: m } : {}
  },
})
fe.autoClear(() => ({ ...state }))

function openCreate() {
  state.name = ''
  state.project = ALL
  fe.reset()
  createOpen.value = true
}

async function create() {
  if (busy.value || !fe.check()) return
  busy.value = true
  try {
    created.value = await api.tokens.create({ name: state.name.trim(), project_id: state.project === ALL ? null : Number(state.project) })
    createOpen.value = false
    await reload()
  } catch (e) {
    fe.fromServer(e)
  } finally {
    busy.value = false
  }
}

async function revoke() {
  if (!revoking.value) return
  revokeBusy.value = true
  try {
    await api.tokens.revoke(revoking.value.id)
    toast.success(`Token "${revoking.value.name}" revoked. It stops working immediately.`)
    revoking.value = null
    await reload()
  } catch (e) {
    toast.error(friendlyError(e).message)
  } finally {
    revokeBusy.value = false
  }
}
</script>

<template>
  <div>
    <PageHeader title="Ingest tokens" subtitle="Tokens let CI pipelines send SARIF results. A token can only call the ingest endpoints.">
      <template v-if="auth.isAdmin" #actions>
        <UButton icon="i-lucide-plus" data-testid="create-token" @click="openCreate">Create token</UButton>
      </template>
    </PageHeader>

    <AdminOnly>
      <LoadingState v-if="pending && !data" />
      <ErrorState v-else-if="error && !data" :error="error" @retry="reload" />
      <UCard v-else-if="data" :ui="{ body: 'p-0 sm:p-0' }">
        <EmptyState v-if="data.length === 0" title="No ingest tokens yet" hint="Create a token to let CI send scan results." />
        <UTable v-else :data="data" :columns="columns" caption="Ingest tokens" data-testid="tokens-table" :ui="{ root: 'overflow-x-auto', caption: 'sr-only' }">
          <template #name-cell="{ row }"><span class="font-medium">{{ row.original.name }}</span></template>
          <template #prefix-cell="{ row }"><span class="font-mono text-xs">{{ row.original.token_prefix }}…</span></template>
          <template #project-cell="{ row }">{{ row.original.project?.name ?? 'All projects' }}</template>
          <template #used-cell="{ row }"><LocalTime :value="row.original.last_used_at" empty="Never" /></template>
          <template #status-cell="{ row }"><UBadge :color="row.original.status === 'active' ? 'success' : 'neutral'" variant="subtle" size="sm">{{ row.original.status === 'active' ? 'Active' : 'Revoked' }}</UBadge></template>
          <template #actions-cell="{ row }">
            <div class="flex justify-end">
              <UButton v-if="row.original.status === 'active'" color="error" variant="ghost" size="xs" :aria-label="`Revoke token ${row.original.name}`" @click="revoking = row.original;">Revoke</UButton>
            </div>
          </template>
        </UTable>
      </UCard>
    </AdminOnly>

    <ModalDialog :open="createOpen" title="Create ingest token" :busy="busy" @close="createOpen = false">
      <UForm id="token-form" :loading-auto="false" :state="state" novalidate class="space-y-4" @submit="create">
        <FormErrorSummary />
        <AppField name="name" label="Name" required help="1 to 100 characters. Shown in the token list and the audit log.">
          <UInput id="tk-name" v-model="state.name" data-autofocus maxlength="100" class="w-full" placeholder="e.g. storefront pipeline" :disabled="busy" />
        </AppField>
        <AppField name="project" label="Restrict to project" hint="Optional">
          <USelect id="tk-project" v-model="state.project" :items="projectItems" class="w-full" :disabled="busy" />
        </AppField>
      </UForm>
      <template #footer>
        <UButton color="neutral" variant="outline" :disabled="busy" @click="createOpen = false;">Cancel</UButton>
        <UButton type="submit" form="token-form" :loading="busy">{{ busy ? 'Creating…' : 'Create token' }}</UButton>
      </template>
    </ModalDialog>

    <ModalDialog :open="!!created" title="Token created" size="lg" @close="created = null">
      <template v-if="created">
        <UAlert color="warning" variant="subtle" icon="i-lucide-triangle-alert" class="mb-3" title="Copy this token now." description="It is shown only once and cannot be retrieved later. Store it in your CI secrets." />
        <div class="flex flex-wrap items-center gap-2">
          <code class="min-w-0 flex-1 break-all rounded bg-elevated px-2 py-1.5 text-xs" data-testid="raw-token">{{ created.secret }}</code>
          <CopyButton :value="created.secret" label="Copy token" />
        </div>
        <h3 class="mb-1 mt-4 text-sm">Example</h3>
        <pre class="overflow-x-auto rounded-md bg-inverted p-3 text-xs leading-5 text-inverted" tabindex="0">{{ ingestCurlExample(origin) }}</pre>
        <p class="mt-1 text-xs text-muted">Set SDRSCAN_TOKEN to the token above in your CI secrets.</p>
      </template>
      <template #footer><UButton data-autofocus @click="created = null;">Done</UButton></template>
    </ModalDialog>

    <ModalDialog :open="!!revoking" title="Revoke token" :busy="revokeBusy" @close="revoking = null">
      <p>Revoke <strong>{{ revoking?.name }}</strong>? Pipelines using it will be rejected immediately. This cannot be undone.</p>
      <template #footer>
        <UButton color="neutral" variant="outline" :disabled="revokeBusy" @click="revoking = null;">Cancel</UButton>
        <UButton color="error" :loading="revokeBusy" data-autofocus @click="revoke">{{ revokeBusy ? 'Revoking…' : 'Revoke token' }}</UButton>
      </template>
    </ModalDialog>
  </div>
</template>
