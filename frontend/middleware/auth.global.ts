import { safeNextPath } from '~/utils/format'

// Probes GET /auth/me once on first load, then guards every route.
export default defineNuxtRouteMiddleware(async (to) => {
  const auth = useAuth()
  if (!auth.loaded) await auth.fetchMe()

  if (to.path === '/login') {
    if (auth.user) return navigateTo(safeNextPath(to.query.next, auth.mustChangePassword ? '/account' : '/'))
    return
  }

  if (!auth.user) {
    const query = to.fullPath !== '/' ? { next: to.fullPath } : {}
    return navigateTo({ path: '/login', query })
  }

  if (auth.mustChangePassword && to.path !== '/account') return navigateTo('/account')
})
