<script setup lang="ts">
import type { DropdownMenuItem, NavigationMenuItem } from '@nuxt/ui'
import { canManageVulnDb } from '~/utils/permissions'

const auth = useAuth()
const route = useRoute()

const links = computed(() => {
  const list: Array<{ label: string, to: string, icon: string, active: boolean }> = [
    { label: 'Projects', to: '/', icon: 'i-lucide-folder', active: route.path === '/' || /^\/(projects|codebases|findings|scans)/.test(route.path) },
    { label: 'Schedules', to: '/schedules', icon: 'i-lucide-calendar-clock', active: route.path === '/schedules' },
  ]
  if (auth.isAdmin) {
    list.push(
      { label: 'Users', to: '/users', icon: 'i-lucide-users', active: route.path === '/users' },
      { label: 'Ingest tokens', to: '/settings/tokens', icon: 'i-lucide-key-round', active: route.path.startsWith('/settings/tokens') },
      { label: 'Activity', to: '/activity', icon: 'i-lucide-activity', active: route.path === '/activity' },
    )
  }
  if (canManageVulnDb(auth.user)) {
    list.push({ label: 'Vulnerability database', to: '/settings/vulndb', icon: 'i-lucide-database', active: route.path.startsWith('/settings/vulndb') })
  }
  return list
})

const navItems = computed<NavigationMenuItem[]>(() => links.value.map(l => ({ label: l.label, to: l.to, icon: l.icon, active: l.active })))
const mobileItems = computed<DropdownMenuItem[][]>(() => [links.value.map(l => ({ label: l.label, to: l.to, icon: l.icon }))])
const userItems = computed<DropdownMenuItem[][]>(() => [
  [{ label: `${auth.user?.username ?? ''} (${auth.user?.role === 'admin' ? 'Admin' : 'Member'})`, type: 'label' }],
  [{ label: 'Account', icon: 'i-lucide-user', to: '/account' }, { label: 'Sign out', icon: 'i-lucide-log-out', onSelect: () => { void auth.logout() } }],
])
</script>

<template>
  <div class="min-h-screen">
    <a href="#main" class="sr-only focus:not-sr-only focus:absolute focus:left-2 focus:top-2 focus:z-50 focus:rounded focus:bg-default focus:px-3 focus:py-2">Skip to main content</a>
    <header class="border-b border-default bg-default">
      <div class="mx-auto flex max-w-7xl items-center gap-3 px-4 py-2">
        <NuxtLink to="/" class="flex items-center gap-2 font-semibold text-highlighted no-underline">
          <span class="grid size-7 place-items-center rounded-md bg-primary text-inverted"><AppIcon name="shield" :size="16" /></span>
          SDRScan
        </NuxtLink>
        <nav aria-label="Main" class="ml-4 hidden flex-1 md:block">
          <UNavigationMenu :items="navItems" orientation="horizontal" />
        </nav>
        <div class="ml-auto flex items-center gap-1">
          <UDropdownMenu :items="mobileItems" class="md:hidden">
            <UButton color="neutral" variant="ghost" size="sm" icon="i-lucide-menu" class="md:hidden" aria-label="Open navigation menu">Menu</UButton>
          </UDropdownMenu>
          <UDropdownMenu :items="userItems" :content="{ align: 'end' }">
            <UButton color="neutral" variant="ghost" size="sm" icon="i-lucide-user" trailing-icon="i-lucide-chevron-down" aria-label="Account menu">
              <span data-testid="current-user">{{ auth.user?.username }}</span>
              <UBadge color="neutral" variant="outline" size="sm" class="ml-1">{{ auth.user?.role === 'admin' ? 'Admin' : 'Member' }}</UBadge>
            </UButton>
          </UDropdownMenu>
        </div>
      </div>
    </header>
    <main id="main" class="mx-auto max-w-7xl px-4 py-6" tabindex="-1">
      <slot />
    </main>
  </div>
</template>
