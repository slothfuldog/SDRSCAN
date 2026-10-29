<script setup lang="ts">
import type { TableColumn } from '@nuxt/ui'
import { canDeleteEntities } from '~/utils/permissions'
import { highestSeverity, totalCount } from '~/utils/severity'
import type { CodebaseRow, Project } from '~/types/api'

const auth = useAuth()
const api = useApi()
const route = useRoute()
const toast = useNotify()
const id = computed(() => Number(route.params.id))

const { data, error, pending, reload } = useLoad(() => api.projects.get(id.value), { watch: [id] })
useHead(() => ({ title: `${data.value?.project.name ?? 'Project'} · SDRScan` }))

const anyScanned = computed(() => !!data.value?.codebases.some(c => c.summary))
const topSeverity = computed(() => data.value?.totals.highest_severity ?? highestSeverity(data.value?.totals))
const editOpen = ref(false)
const deleteProjectOpen = ref(false)
const moving = ref<CodebaseRow | null>(null)
const deleting = ref<CodebaseRow | null>(null)

const columns: TableColumn<CodebaseRow>[] = [
  { id: 'codebase', header: 'Codebase' },
  { id: 'type', header: 'Type' },
  { id: 'scan', header: 'Last scan' },
  { id: 'findings', header: 'Findings (latest state)' },
  { id: 'highest', header: 'Highest' },
  { id: 'actions', header: () => h('span', { class: 'sr-only' }, 'Actions') },
]

async function projectSaved(_: Project) {
  editOpen.value = false
  toast.success('Project updated.')
  await reload()
}

async function projectDeleted() {
  toast.success('Project deleted.')
  await navigateTo('/')
}

async function codebaseMoved() {
  const name = moving.value?.name
  moving.value = null
  toast.success(`Codebase "${name}" moved. Its scan history moved with it.`)
  await reload()
}

async function codebaseDeleted() {
  const name = deleting.value?.name
  deleting.value = null
  toast.success(`Codebase "${name}" deleted.`)
  await reload()
}
</script>

<template>
  <div>
    <LoadingState v-if="pending && data?.project.id !== id" />
    <ErrorState v-else-if="error && !data" :error="error" not-found-message="Project not found." @retry="reload" />
    <template v-else-if="data">
      <PageHeader :title="data.project.name" :subtitle="data.project.description || undefined">
        <template #breadcrumb>
          <AppBreadcrumb :items="[{ label: 'Projects', to: '/' }, { label: data.project.name }]" />
        </template>
        <template #actions>
          <UButton color="neutral" variant="outline" icon="i-lucide-pencil" @click="editOpen = true;">Edit</UButton>
          <UButton v-if="canDeleteEntities(auth.user)" color="error" variant="outline" icon="i-lucide-trash-2" @click="deleteProjectOpen = true;">Delete</UButton>
          <UButton :to="`/codebases/new?project=${data.project.id}`" icon="i-lucide-plus" data-testid="add-codebase">Add codebase</UButton>
        </template>
      </PageHeader>

      <UCard class="mb-4" data-testid="project-totals">
        <h2 id="totals-h" class="mb-2 text-base">Project total</h2>
        <template v-if="anyScanned">
          <div class="flex flex-wrap items-center gap-3">
            <SeverityCounts :summary="data.totals" />
            <p class="text-muted">
              <template v-if="topSeverity">Highest severity: <SeverityBadge :severity="topSeverity" /></template>
              <template v-else>No findings in the latest scans.</template>
            </p>
          </div>
          <p class="mt-1 text-xs text-muted">{{ totalCount(data.totals) }} findings across scanned codebases (latest state of each).</p>
        </template>
        <p v-else class="text-muted">Not scanned yet. Run a scan on a codebase to see results here.</p>
      </UCard>

      <ErrorState v-if="error" :error="error" class="mb-3" @retry="reload" />

      <UCard :ui="{ body: 'p-0 sm:p-0' }">
        <h2 id="cb-h" class="px-4 pt-4 text-base">Codebases</h2>
        <EmptyState v-if="data.codebases.length === 0" title="No codebases yet" hint="Add a repository to scan with SAST.">
          <UButton :to="`/codebases/new?project=${data.project.id}`" icon="i-lucide-plus">Add codebase</UButton>
        </EmptyState>
        <UTable v-else :data="data.codebases" :columns="columns" :caption="`Codebases in ${data.project.name}`" data-testid="codebases-table" :ui="{ root: 'mt-2 overflow-x-auto', td: 'align-top', caption: 'sr-only' }">
          <template #codebase-cell="{ row }">
            <div class="min-w-[10rem]">
              <NuxtLink :to="`/codebases/${row.original.id}`" class="font-medium text-primary hover:underline">{{ row.original.name }}</NuxtLink>
              <p v-if="row.original.subdirectory" class="font-mono text-xs text-muted">{{ row.original.subdirectory }}</p>
            </div>
          </template>
          <template #type-cell="{ row }">
            <div class="flex flex-wrap gap-1">
              <UBadge color="neutral" variant="outline" size="sm">{{ row.original.target_type === 'url' ? 'URL' : 'Repo' }}</UBadge>
              <DastStatusBadge v-if="row.original.target_type === 'url'" :status="row.original.dast_status" />
            </div>
          </template>
          <template #scan-cell="{ row }">
            <div v-if="row.original.latest_scan" class="min-w-[11rem]">
              <div class="flex flex-wrap items-center gap-1.5">
                <NuxtLink :to="`/scans/${row.original.latest_scan.id}`" class="text-primary hover:underline">#{{ row.original.latest_scan.id }}</NuxtLink>
                <UBadge color="neutral" variant="outline" size="sm">{{ row.original.latest_scan.coverage === 'partial' ? 'Partial' : 'Full' }}</UBadge>
                <ScanStatusBadge :status="row.original.latest_scan.status" />
              </div>
              <p class="text-xs text-muted"><LocalTime :value="row.original.latest_scan.started_at" /><span v-if="row.original.latest_scan.ref"> · <code>{{ row.original.latest_scan.ref }}</code></span></p>
            </div>
            <span v-else class="text-muted">&ndash;</span>
          </template>
          <template #findings-cell="{ row }">
            <SeverityCounts v-if="row.original.summary" :summary="row.original.summary" compact />
            <span v-else class="text-muted" data-testid="not-scanned">Not scanned yet</span>
          </template>
          <template #highest-cell="{ row }">
            <SeverityBadge v-if="row.original.summary?.highest_severity" :severity="row.original.summary.highest_severity" />
            <span v-else-if="row.original.summary" class="text-muted">None</span>
            <span v-else class="text-muted">&ndash;</span>
          </template>
          <template #actions-cell="{ row }">
            <div class="flex flex-wrap items-start justify-end gap-1">
              <RunScanButton :codebase="row.original" small />
              <UButton color="neutral" variant="ghost" size="xs" icon="i-lucide-move" :aria-label="`Move codebase ${row.original.name}`" @click="moving = row.original;">Move</UButton>
              <UButton v-if="canDeleteEntities(auth.user)" color="error" variant="ghost" size="xs" icon="i-lucide-trash-2" :aria-label="`Delete codebase ${row.original.name}`" @click="deleting = row.original;">Delete</UButton>
            </div>
          </template>
        </UTable>
      </UCard>

      <ProjectFormDialog :open="editOpen" :project="data.project" @close="editOpen = false" @saved="projectSaved" />
      <ConfirmDeleteDialog
        v-if="deleteProjectOpen" :open="deleteProjectOpen" kind="Project" :name="data.project.name"
        :action="() => api.projects.remove(data!.project.id, data!.project.name)" @close="deleteProjectOpen = false" @deleted="projectDeleted"
      />
      <MoveCodebaseDialog
        v-if="moving" :open="!!moving" :codebase-id="moving.id" :codebase-name="moving.name" :current-project-id="data.project.id"
        @close="moving = null" @moved="codebaseMoved"
      />
      <ConfirmDeleteDialog
        v-if="deleting" :open="!!deleting" kind="Codebase" :name="deleting.name"
        :action="() => api.codebases.remove(deleting!.id, deleting!.name)" @close="deleting = null" @deleted="codebaseDeleted"
      />
    </template>
  </div>
</template>
