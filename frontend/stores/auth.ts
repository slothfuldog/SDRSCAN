import { defineStore } from 'pinia'
import { createApiClient } from '~/utils/apiClient'
import { createEndpoints } from '~/utils/endpoints'
import { isApiError } from '~/utils/errors'
import type { ApiError } from '~/utils/errors'
import type { User } from '~/types/api'

/**
 * Session state. The session cookie (sdrscan_session) is HttpOnly and invisible to JS; the CSRF token
 * is kept in memory only, never in localStorage/sessionStorage.
 */
export const useAuth = defineStore('auth', () => {
  const config = useRuntimeConfig()
  const router = useRouter()

  const user = ref<User | null>(null)
  const csrfToken = ref<string | null>(null)
  const mustChangePassword = ref(false)
  const loaded = ref(false)
  const bootError = ref<ApiError | null>(null)

  // Own client: the 401 handling here must not depend on the useApi() composable (which depends on this store).
  const api = createEndpoints(createApiClient({
    baseURL: config.public.apiBase,
    getCsrfToken: () => csrfToken.value,
  }))

  const isAdmin = computed(() => user.value?.role === 'admin')
  const hasDastAccess = computed(() => !!user.value && (user.value.role === 'admin' || user.value.can_run_dast))

  function setSession(u: User, csrf: string, mustChange: boolean) {
    user.value = u
    csrfToken.value = csrf
    mustChangePassword.value = mustChange
  }

  function clear() {
    user.value = null
    csrfToken.value = null
    mustChangePassword.value = false
  }

  /** Called by every 401 from the shared API client: forget the session and go to the login page. */
  async function sessionExpired() {
    clear()
    const current = router.currentRoute.value
    if (current.path !== '/login') {
      const query = current.fullPath !== '/' ? { next: current.fullPath } : {}
      await navigateTo({ path: '/login', query })
    }
  }

  async function fetchMe(): Promise<void> {
    bootError.value = null
    try {
      const res = await api.auth.me()
      setSession(res.user, res.csrf_token, res.must_change_password)
    } catch (e) {
      clear()
      if (isApiError(e) && e.status !== 401) bootError.value = e
    } finally {
      loaded.value = true
    }
  }

  async function login(username: string, password: string): Promise<User> {
    const res = await api.auth.login(username, password)
    setSession(res.user, res.csrf_token, res.must_change_password ?? res.user.must_change_password ?? false)
    loaded.value = true
    bootError.value = null
    return res.user
  }

  async function logout(): Promise<void> {
    try {
      await api.auth.logout()
    } catch {
      // The session is dropped locally regardless.
    }
    clear()
    await navigateTo('/login')
  }

  /** After a successful password change the "must change" gate is lifted. */
  function passwordChanged() {
    mustChangePassword.value = false
    if (user.value) user.value = { ...user.value, must_change_password: false }
  }

  return { user, csrfToken, mustChangePassword, loaded, bootError, isAdmin, hasDastAccess, fetchMe, login, logout, clear, sessionExpired, passwordChanged }
})
