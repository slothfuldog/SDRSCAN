<script setup lang="ts">
import { friendlyError } from '~/utils/errors'
import { displayUser } from '~/utils/format'
import { canEditSchedule } from '~/utils/permissions'
import { describeSchedule, scheduleStatusLabel, suspendedReasonText } from '~/utils/schedule'
import type { TableColumn } from '@nuxt/ui'
import type { ScheduleListItem } from '~/types/api'

useHead({ title: 'Schedules · SDRScan' })

const auth = useAuth()
const api = useApi()
const toast = useNotify()
const page = useRouteQuery('page', 1)
const status = useRouteQuery<string>('status', '', { resetPage: true })

const { data, error, pending, reload } = useLoad(
  () => api.schedules.list({ page: page.value, page_size: 50, status: status.value === 'active' || status.value === 'suspended' ? status.value : undefined }),
  { watch: [page, status] },
)

const ALL = '__all__'
const statusItems = [{ label: 'All', value: ALL }, { label: 'Active', value: 'active' }, { label: 'Suspended', value: 'suspended' }]
const columns: TableColumn<ScheduleListItem>[] = [
  { id: 'codebase', header: 'Codebase' },
  { id: 'project', header: 'Project' },
  { id: 'schedule', header: 'Schedule' },
  { id: 'status', header: 'Status' },
  { id: 'owner', header: 'Owner' },
  { id: 'last', header: 'Last queued' },
  { id: 'next', header: 'Next run' },
  { id: 'actions', header: () => h('span', { class: 'sr-only' }, 'Actions') },
]
const busyId = ref<number | null>(null)
const deleting = ref<ScheduleListItem | null>(null)
const editable = (s: ScheduleListItem) => canEditSchedule(auth.user, s.codebase)

async function resume(s: ScheduleListItem) {
  busyId.value = s.codebase.id
  try {
    await api.schedules.resume(s.codebase.id)
    toast.success(`Schedule of "${s.codebase.name}" resumed. You are now its owner.`)
    await reload()
  } catch (e) {
    toast.error(friendlyError(e).message)
  } finally {
    busyId.value = null
  }
}

async function confirmDelete() {
  const s = deleting.value
  if (!s) return
  busyId.value = s.codebase.id
  try {
    await api.schedules.remove(s.codebase.id)
    toast.success(`Schedule of "${s.codebase.name}" deleted.`)
    deleting.value = null
    await reload()
  } catch (e) {
    toast.error(friendlyError(e).message)
  } finally {
    busyId.value = null
  }
}
</script>

<template>
  <div>
    <PageHeader title="Schedules" subtitle="Automatic scans across all projects. Times are in UTC unless shown in your local time." />

    <UFormField label="Status" name="status" class="mb-3 max-w-xs">
      <USelect id="sched-status" :model-value="status || ALL" :items="statusItems" class="w-full" @update:model-value="status = $event === ALL ? '' : String($event)" />
    </UFormField>

    <LoadingState v-if="pending && !data" />
    <ErrorState v-else-if="error && !data" :error="error" @retry="reload" />
    <UCard v-else-if="data" :ui="{ body: 'p-0 sm:p-0' }">
      <ErrorState v-if="error" :error="error" class="m-3" @retry="reload" />
      <EmptyState v-if="data.items.length === 0" :title="status ? `No ${status} schedules` : 'No schedules yet'" hint="Set a schedule in a codebase's settings." />
      <template v-else>
        <UTable :data="data.items" :columns="columns" caption="Schedules" data-testid="schedules-table" :ui="{ root: 'overflow-x-auto', td: 'align-top', caption: 'sr-only' }">
          <template #codebase-cell="{ row }">
            <NuxtLink :to="`/codebases/${row.original.codebase.id}/settings`" class="font-medium text-primary hover:underline">{{ row.original.codebase.name }}</NuxtLink>
            <UBadge color="neutral" variant="outline" size="sm" class="ml-1">{{ row.original.codebase.target_type === 'url' ? 'URL' : 'Repo' }}</UBadge>
          </template>
          <template #project-cell="{ row }"><NuxtLink :to="`/projects/${row.original.project.id}`" class="text-primary hover:underline">{{ row.original.project.name }}</NuxtLink></template>
          <template #schedule-cell="{ row }"><span class="min-w-[10rem]">{{ describeSchedule(row.original.cron) }}</span></template>
          <template #status-cell="{ row }">
            <UBadge :color="row.original.status === 'active' ? 'success' : 'warning'" variant="subtle" size="sm">{{ scheduleStatusLabel(row.original.status).label }}</UBadge>
            <p v-if="row.original.status === 'suspended'" class="mt-1 text-xs text-muted">{{ suspendedReasonText(row.original.suspended_reason) }}<template v-if="row.original.suspended_at"> &middot; <LocalTime :value="row.original.suspended_at" /></template></p>
          </template>
          <template #owner-cell="{ row }">{{ displayUser(row.original.owner) }}</template>
          <template #last-cell="{ row }"><LocalTime :value="row.original.last_enqueued_at" empty="Never" /></template>
          <template #next-cell="{ row }"><LocalTime :value="row.original.status === 'suspended' ? null : row.original.next_run_at" empty="–" /></template>
          <template #actions-cell="{ row }">
            <div class="flex flex-wrap justify-end gap-1">
              <UButton
                v-if="row.original.status === 'suspended'" size="xs" icon="i-lucide-play" :disabled="!editable(row.original) || busyId === row.original.codebase.id"
                :title="editable(row.original) ? undefined : 'You need DAST access to resume a schedule of a URL target.'" :aria-label="`Resume schedule of ${row.original.codebase.name}`" @click="resume(row.original)"
              >Resume</UButton>
              <UButton
                color="error" variant="ghost" size="xs" icon="i-lucide-trash-2" :disabled="!editable(row.original) || busyId === row.original.codebase.id"
                :aria-label="`Delete schedule of ${row.original.codebase.name}`" @click="deleting = row.original;"
              >Delete</UButton>
            </div>
          </template>
        </UTable>
        <PagerBar :page="data.page" :page-size="data.page_size" :total="data.total" @update:page="page = $event" />
      </template>
    </UCard>

    <ModalDialog :open="!!deleting" title="Delete schedule" :busy="busyId !== null" @close="deleting = null">
      <p>Delete the schedule of <strong>{{ deleting?.codebase.name }}</strong>? Automatic scans stop.</p>
      <template #footer>
        <UButton color="neutral" variant="outline" :disabled="busyId !== null" @click="deleting = null;">Cancel</UButton>
        <UButton color="error" :loading="busyId !== null" data-autofocus @click="confirmDelete">Delete schedule</UButton>
      </template>
    </ModalDialog>
  </div>
</template>
