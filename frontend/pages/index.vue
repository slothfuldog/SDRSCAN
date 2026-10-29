<script setup lang="ts">
import type { TableColumn } from '@nuxt/ui'
import { canDeleteEntities } from '~/utils/permissions'
import type { Project, ProjectListItem } from '~/types/api'

useHead({ title: 'Projects · SDRScan' })

const auth = useAuth()
const api = useApi()
const toast = useNotify()
const page = useRouteQuery('page', 1)
const pageSize = 50

const { data, error, pending, reload } = useLoad(() => api.projects.list({ page: page.value, page_size: pageSize }), { watch: [page] })

const formOpen = ref(false)
const editing = ref<Project | null>(null)
const deleting = ref<ProjectListItem | null>(null)

const columns: TableColumn<ProjectListItem>[] = [
  { id: 'name', header: 'Name' },
  { id: 'codebases', header: 'Codebases' },
  { id: 'findings', header: 'Findings (latest state)' },
  { id: 'highest', header: 'Highest severity' },
  { id: 'actions', header: () => h('span', { class: 'sr-only' }, 'Actions') },
]

function openCreate() { editing.value = null; formOpen.value = true }
function openEdit(p: ProjectListItem) { editing.value = p; formOpen.value = true }

async function saved(p: Project) {
  formOpen.value = false
  toast.success(editing.value ? `Project "${p.name}" updated.` : `Project "${p.name}" created.`)
  await reload()
}

async function deleted() {
  const name = deleting.value?.name
  deleting.value = null
  toast.success(`Project "${name}" deleted.`)
  if (data.value && data.value.items.length === 1 && page.value > 1) page.value = page.value - 1
  else await reload()
}
</script>

<template>
  <div>
    <PageHeader title="Projects" subtitle="Group codebases and see which ones are most at risk.">
      <template #actions>
        <UButton icon="i-lucide-plus" data-testid="create-project" @click="openCreate">Create project</UButton>
      </template>
    </PageHeader>

    <LoadingState v-if="pending && !data" />
    <ErrorState v-else-if="error && !data" :error="error" @retry="reload" />
    <template v-else-if="data">
      <ErrorState v-if="error" :error="error" class="mb-3" @retry="reload" />
      <UCard :ui="{ body: 'p-0 sm:p-0' }">
        <EmptyState v-if="data.items.length === 0" title="No projects yet" hint="Create a project, then add the codebases you want to scan.">
          <UButton icon="i-lucide-plus" @click="openCreate">Create project</UButton>
        </EmptyState>
        <template v-else>
          <UTable :data="data.items" :columns="columns" caption="Projects" data-testid="projects-table" :ui="{ root: 'overflow-x-auto', td: 'align-top', caption: 'sr-only' }">
            <template #name-cell="{ row }">
              <div class="min-w-[12rem]">
                <NuxtLink :to="`/projects/${row.original.id}`" class="font-medium text-primary hover:underline">{{ row.original.name }}</NuxtLink>
                <p v-if="row.original.description" class="line-clamp-1 text-xs text-muted">{{ row.original.description }}</p>
              </div>
            </template>
            <template #codebases-cell="{ row }"><span class="tabular-nums">{{ row.original.codebase_count }}</span></template>
            <template #findings-cell="{ row }">
              <SeverityCounts v-if="row.original.codebase_count > 0" :summary="row.original.totals" compact />
              <span v-else class="text-muted">No codebases</span>
            </template>
            <template #highest-cell="{ row }">
              <SeverityBadge v-if="row.original.highest_severity" :severity="row.original.highest_severity" />
              <span v-else class="text-muted">{{ row.original.codebase_count > 0 ? 'No findings' : '–' }}</span>
            </template>
            <template #actions-cell="{ row }">
              <div class="flex justify-end gap-1">
                <UButton color="neutral" variant="ghost" size="xs" icon="i-lucide-pencil" :aria-label="`Edit project ${row.original.name}`" @click="openEdit(row.original)">Edit</UButton>
                <UButton v-if="canDeleteEntities(auth.user)" color="error" variant="ghost" size="xs" icon="i-lucide-trash-2" :aria-label="`Delete project ${row.original.name}`" @click="deleting = row.original;">Delete</UButton>
              </div>
            </template>
          </UTable>
          <PagerBar :page="data.page" :page-size="data.page_size" :total="data.total" @update:page="page = $event" />
        </template>
      </UCard>
    </template>

    <ProjectFormDialog :open="formOpen" :project="editing" @close="formOpen = false" @saved="saved" />
    <ConfirmDeleteDialog
      v-if="deleting" :open="!!deleting" kind="Project" :name="deleting.name"
      :action="() => api.projects.remove(deleting!.id, deleting!.name)" @close="deleting = null" @deleted="deleted"
    />
  </div>
</template>
