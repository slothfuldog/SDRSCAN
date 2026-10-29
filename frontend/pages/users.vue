<script setup lang="ts">
import type { DropdownMenuItem, TableColumn } from '@nuxt/ui'
import { friendlyError } from '~/utils/errors'
import type { PatchUserBody, Role, UserRow } from '~/types/api'

useHead({ title: 'Users · SDRScan' })

const auth = useAuth()
const api = useApi()
const toast = useNotify()
const page = useRouteQuery('page', 1)

const { data, error, pending, reload } = useLoad(
  () => (auth.isAdmin ? api.users.list({ page: page.value, page_size: 50 }) : Promise.resolve(undefined)),
  { watch: [page] },
)

const createOpen = ref(false)
const resetting = ref<UserRow | null>(null)
const busyId = ref<number | null>(null)
const roleItems = [{ label: 'Admin', value: 'admin' }, { label: 'Member', value: 'member' }]

const columns: TableColumn<UserRow>[] = [
  { id: 'username', header: 'Username' },
  { id: 'role', header: 'Role' },
  { id: 'dast', header: 'DAST access' },
  { id: 'status', header: 'Status' },
  { id: 'last', header: 'Last sign-in' },
  { id: 'actions', header: () => h('span', { class: 'sr-only' }, 'Actions') },
]

async function patch(u: UserRow, body: PatchUserBody, okMessage: string) {
  busyId.value = u.id
  try {
    await api.users.patch(u.id, body)
    toast.success(okMessage)
  } catch (e) {
    toast.error(friendlyError(e).message)
  } finally {
    busyId.value = null
    await reload()
  }
}

const changeRole = (u: UserRow, role: Role) => (role === u.role ? undefined : patch(u, { role }, `${u.username} is now ${role === 'admin' ? 'an Admin' : 'a Member'}.`))
const toggleDast = (u: UserRow, on: boolean) => patch(u, { can_run_dast: on }, `DAST access ${on ? 'granted to' : 'removed from'} ${u.username}.`)
const toggleActive = (u: UserRow) => patch(u, { is_active: !u.is_active }, `${u.username} ${u.is_active ? 'deactivated' : 'activated'}.`)

const rowMenu = (u: UserRow): DropdownMenuItem[][] => [[
  { label: 'Reset password', icon: 'i-lucide-key-round', onSelect: () => { resetting.value = u } },
  { label: u.is_active ? 'Deactivate' : 'Activate', icon: u.is_active ? 'i-lucide-user-x' : 'i-lucide-user-check', color: u.is_active ? 'error' : 'primary', onSelect: () => { void toggleActive(u) } },
]]

async function created(u: UserRow) {
  createOpen.value = false
  toast.success(`User "${u.username}" created. They must change the password at first sign-in.`)
  await reload()
}

function passwordReset() {
  const name = resetting.value?.username
  resetting.value = null
  toast.success(`Password reset for ${name}. They must change it at next sign-in.`)
}
</script>

<template>
  <div>
    <PageHeader title="Users" subtitle="Create accounts, set roles and control DAST access.">
      <template v-if="auth.isAdmin" #actions>
        <UButton icon="i-lucide-plus" data-testid="create-user" @click="createOpen = true;">Create user</UButton>
      </template>
    </PageHeader>

    <AdminOnly>
      <LoadingState v-if="pending && !data" />
      <ErrorState v-else-if="error && !data" :error="error" @retry="reload" />
      <UCard v-else-if="data" :ui="{ body: 'p-0 sm:p-0' }">
        <ErrorState v-if="error" :error="error" class="m-3" @retry="reload" />
        <UTable :data="data.items" :columns="columns" caption="Users" data-testid="users-table" :ui="{ root: 'overflow-x-auto', caption: 'sr-only' }">
          <template #username-cell="{ row }"><span class="font-medium">{{ row.original.username }}</span><span v-if="row.original.id === auth.user?.id" class="text-muted"> (you)</span></template>
          <template #role-cell="{ row }">
            <USelect
              :id="`role-${row.original.id}`" :model-value="row.original.role" :items="roleItems" size="sm" class="w-32" :disabled="busyId === row.original.id"
              :aria-label="`Role of ${row.original.username}`" @update:model-value="changeRole(row.original, $event as Role)"
            />
          </template>
          <template #dast-cell="{ row }">
            <UCheckbox
              :model-value="row.original.role === 'admin' || row.original.can_run_dast" :disabled="row.original.role === 'admin' || busyId === row.original.id"
              :aria-label="`DAST access for ${row.original.username}`" :label="row.original.role === 'admin' ? 'Always' : undefined" @update:model-value="toggleDast(row.original, $event === true)"
            />
          </template>
          <template #status-cell="{ row }">
            <UBadge :color="row.original.is_active ? 'success' : 'neutral'" variant="subtle" size="sm">{{ row.original.is_active ? 'Active' : 'Deactivated' }}</UBadge>
          </template>
          <template #last-cell="{ row }"><span class="whitespace-nowrap"><LocalTime :value="row.original.last_login_at" empty="Never" /></span></template>
          <template #actions-cell="{ row }">
            <div class="flex justify-end">
              <UDropdownMenu :items="rowMenu(row.original)" :content="{ align: 'end' }">
                <UButton color="neutral" variant="ghost" size="xs" icon="i-lucide-ellipsis-vertical" :disabled="busyId === row.original.id" :aria-label="`Actions for ${row.original.username}`" />
              </UDropdownMenu>
            </div>
          </template>
        </UTable>
        <PagerBar :page="data.page" :page-size="data.page_size" :total="data.total" @update:page="page = $event" />
      </UCard>
    </AdminOnly>

    <CreateUserDialog :open="createOpen" @close="createOpen = false" @created="created" />
    <ResetPasswordDialog :open="!!resetting" :user="resetting" @close="resetting = null" @done="passwordReset" />
  </div>
</template>
