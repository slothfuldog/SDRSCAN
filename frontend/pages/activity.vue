<script setup lang="ts">
import type { TableColumn } from '@nuxt/ui'
import type { AuditEntry } from '~/types/api'

useHead({ title: 'Activity · SDRScan' })

const auth = useAuth()
const api = useApi()
const page = useRouteQuery('page', 1)

const { data, error, pending, reload } = useLoad(
  () => (auth.isAdmin ? api.audit.list({ page: page.value, page_size: 50 }) : Promise.resolve(undefined)),
  { watch: [page] },
)

const columns: TableColumn<AuditEntry>[] = [
  { id: 'at', header: 'When' },
  { accessorKey: 'actor_name', header: 'Who' },
  { id: 'action', header: 'Action' },
  { id: 'target', header: 'Target' },
]

const LABEL: Record<string, string> = {
  login_failed: 'Failed sign-in', user_created: 'User created', user_role_changed: 'Role changed', user_disabled: 'User deactivated',
  password_reset: 'Password reset', user_dast_access_changed: 'DAST access changed', project_deleted: 'Project deleted',
  codebase_deleted: 'Codebase deleted', token_created: 'Token created', token_revoked: 'Token revoked',
  dast_target_registered: 'DAST target registered', dast_target_confirmed: 'DAST target confirmed', dast_target_reset: 'DAST target reset',
  dast_scan_started: 'DAST scan started',
  vulndb_update_started: 'Vulnerability database update started', vulndb_update_finished: 'Vulnerability database update finished', vulndb_update_cancelled: 'Vulnerability database update cancelled',
  schedule_set: 'Schedule set', schedule_deleted: 'Schedule deleted', schedule_resumed: 'Schedule resumed', schedule_suspended: 'Schedule suspended',
}
</script>

<template>
  <div>
    <PageHeader title="Activity" subtitle="Recent security-relevant events. Passwords, tokens and finding contents are never logged." />
    <AdminOnly>
      <LoadingState v-if="pending && !data" />
      <ErrorState v-else-if="error && !data" :error="error" @retry="reload" />
      <UCard v-else-if="data" :ui="{ body: 'p-0 sm:p-0' }">
        <EmptyState v-if="data.items.length === 0" title="No activity recorded yet" />
        <template v-else>
          <UTable :data="data.items" :columns="columns" caption="Activity log" data-testid="activity-table" :ui="{ root: 'overflow-x-auto', caption: 'sr-only' }">
            <template #at-cell="{ row }"><span class="whitespace-nowrap"><LocalTime :value="row.original.at" /></span></template>
            <template #action-cell="{ row }">{{ LABEL[row.original.action] ?? row.original.action }}</template>
            <template #target-cell="{ row }"><span class="break-all">{{ row.original.target }}</span></template>
          </UTable>
          <PagerBar :page="data.page" :page-size="data.page_size" :total="data.total" @update:page="page = $event" />
        </template>
      </UCard>
    </AdminOnly>
  </div>
</template>
