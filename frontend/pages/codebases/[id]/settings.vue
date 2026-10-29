<script setup lang="ts">
import { canConfirmTarget, canDeleteEntities } from '~/utils/permissions'
import { displayUser } from '~/utils/format'
import type { Codebase } from '~/types/api'

useHead({ title: 'Codebase settings · SDRScan' })

const { codebase, reload } = useCodebase()
const auth = useAuth()
const api = useApi()
const toast = useNotify()
const confirmOpen = ref(false)
const deleteOpen = ref(false)

async function saved(cb: Codebase) {
  toast.success('Codebase settings saved.')
  if (cb.dast?.status === 'pending_confirmation' && codebase.value?.dast?.status === 'confirmed') {
    toast.info('The target is now Pending confirmation. An Admin must confirm authorization again. Scheduled scans are skipped until then.')
  }
  if (codebase.value?.dast_auth && codebase.value.dast_auth.type !== 'none' && cb.dast_auth?.type === 'none') {
    toast.info('The base URL moved to another host, so the saved credentials were removed. Enter them again for the new host.')
  }
  await reload()
}

async function confirmed() {
  confirmOpen.value = false
  toast.success('Authorization confirmed. DAST scans can run on this target.')
  await reload()
}

async function deleted() {
  const pid = codebase.value?.project.id
  toast.success('Codebase deleted.')
  await navigateTo(pid ? `/projects/${pid}` : '/')
}
</script>

<template>
  <div v-if="codebase" class="max-w-3xl space-y-6">
    <UCard v-if="codebase.dast" data-testid="target-status">
      <h2 id="target-h" class="mb-2 text-base">Target authorization</h2>
      <p class="flex flex-wrap items-center gap-2"><DastStatusBadge :status="codebase.dast.status" /></p>
      <dl class="mt-3 grid grid-cols-[10rem_1fr] gap-y-1">
        <template v-if="codebase.dast.registered_by"><dt class="text-muted">Registered by</dt><dd>{{ displayUser(codebase.dast.registered_by) }}</dd></template>
        <template v-if="codebase.dast.status === 'confirmed'">
          <dt class="text-muted">Confirmed by</dt><dd>{{ displayUser(codebase.dast.confirmed_by) }}</dd>
          <dt class="text-muted">Confirmed at</dt><dd><LocalTime :value="codebase.dast.confirmed_at" /></dd>
        </template>
      </dl>
      <p v-if="codebase.dast.status !== 'confirmed'" class="mt-2 text-warning">An Admin must confirm authorization for this target first.</p>
      <div v-if="canConfirmTarget(auth.user) && codebase.dast.status !== 'confirmed'" class="mt-3">
        <UButton icon="i-lucide-check" data-testid="confirm-authorization" @click="confirmOpen = true;">Confirm authorization</UButton>
      </div>
    </UCard>

    <UCard>
      <h2 id="settings-h" class="mb-4 text-base">Codebase settings</h2>
      <CodebaseForm :key="`${codebase.id}-${codebase.updated_at}-${codebase.base_url}`" mode="edit" :codebase="codebase" @saved="saved" />
    </UCard>

    <DastAuthSettings v-if="codebase.target_type === 'url'" :key="`auth-${codebase.id}-${codebase.base_url}-${codebase.dast_auth?.updated_at}-${codebase.dast_auth?.type}`" :codebase="codebase" @saved="reload" />
    <DastCrawlSettings v-if="codebase.target_type === 'url'" :key="`crawl-${codebase.id}-${codebase.updated_at}`" :codebase="codebase" @saved="reload" />
    <ActiveScanningSettings
      v-if="codebase.target_type === 'url'"
      :key="`active-${codebase.id}-${codebase.base_url}-${codebase.dast_active?.authorized}-${codebase.dast_active?.openapi_spec_url}`"
      :codebase="codebase" @saved="reload"
    />

    <ScheduleSettings :key="`sched-${codebase.id}-${codebase.schedule?.cron}-${codebase.schedule?.status}-${codebase.schedule?.owner?.id}`" :codebase="codebase" @saved="reload" />

    <UCard v-if="canDeleteEntities(auth.user)" :ui="{ root: 'ring-error/40' }">
      <h2 id="danger-h" class="mb-1 text-base text-error">Danger zone</h2>
      <p class="mb-3 text-muted">Deleting this codebase permanently removes all of its scans and findings.</p>
      <UButton color="error" icon="i-lucide-trash-2" @click="deleteOpen = true;">Delete codebase</UButton>
    </UCard>

    <ConfirmAuthorizationDialog :open="confirmOpen" :codebase="codebase" @close="confirmOpen = false" @confirmed="confirmed" />
    <ConfirmDeleteDialog
      v-if="deleteOpen" :open="deleteOpen" kind="Codebase" :name="codebase.name"
      :action="() => api.codebases.remove(codebase!.id, codebase!.name)" @close="deleteOpen = false" @deleted="deleted"
    />
  </div>
</template>
